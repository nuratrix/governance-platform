"""
Incident Agent - Auto Healer — Multi-Account Edition
Executes safe automated remediation actions in the target account:
  - Restart failed ECS tasks
  - Reboot impaired EC2 instances
  - Scale out Auto Scaling Groups
All actions are logged to DynamoDB for audit trail.
"""

import boto3
import logging
import os
from datetime import datetime, timezone
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")

FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "governance-platform-findings")


def lambda_handler(event, context, session=None):
    scan_id       = event.get("scan_id", "manual")
    action        = event.get("action", "")
    resource_id   = event.get("resource_id", "")
    approved_by   = event.get("approved_by", "")
    reason        = event.get("reason", "")
    account_id    = event.get("account_id", "")
    account_name  = event.get("account_name", "")
    logger.info(f"Auto-heal — account={account_id} action={action} resource={resource_id}")

    s   = session or boto3
    ecs = s.client("ecs")
    ec2 = s.client("ec2")
    asg = s.client("autoscaling")

    if action == "restart_ecs_tasks":
        return _restart_ecs_tasks(
            ecs, event.get("cluster"), event.get("service"),
            approved_by, reason, scan_id, account_id
        )
    elif action == "reboot_ec2":
        return _reboot_ec2(ec2, resource_id, approved_by, reason, scan_id, account_id)
    elif action == "scale_asg":
        return _scale_asg(
            asg, resource_id,
            int(event.get("desired_capacity", 0)),
            approved_by, reason, scan_id, account_id
        )
    else:
        return {"success": False, "message": f"Unknown action: {action}"}


def _restart_ecs_tasks(ecs, cluster, service, approved_by, reason, scan_id, account_id):
    """Stop all running tasks in a service — ECS will restart them automatically."""
    if not cluster or not service:
        return {"success": False, "message": "cluster and service are required"}

    if not approved_by:
        return {"success": False,
                "message": "approved_by is required. Call escalate_to_human first."}

    try:
        tasks = ecs.list_tasks(cluster=cluster, serviceName=service)["taskArns"]
        if not tasks:
            return {"success": True, "message": "No running tasks found", "restarted": 0}

        stopped = 0
        for task_arn in tasks:
            ecs.stop_task(
                cluster = cluster,
                task    = task_arn,
                reason  = f"Incident Agent restart: {reason}",
            )
            stopped += 1

        _audit(scan_id, "RESTART_ECS_TASKS",
               f"[{account_id}] Stopped {stopped} tasks in {cluster}/{service}. "
               f"Approved by: {approved_by}. Reason: {reason}")

        return {
            "success":       True,
            "message":       f"Stopped {stopped} tasks in {service}. ECS will restart them.",
            "tasks_stopped": stopped,
            "cluster":       cluster,
            "service":       service,
        }
    except Exception as e:
        logger.error(f"ECS restart failed: {e}")
        return {"success": False, "message": str(e)}


def _reboot_ec2(ec2, instance_id, approved_by, reason, scan_id, account_id):
    """Reboot an EC2 instance that is failing status checks."""
    if not instance_id:
        return {"success": False, "message": "instance_id is required"}

    if not approved_by:
        return {"success": False,
                "message": "approved_by is required. Call escalate_to_human first."}

    try:
        desc     = ec2.describe_instances(InstanceIds=[instance_id])
        instance = desc["Reservations"][0]["Instances"][0]
        state    = instance["State"]["Name"]

        if state != "running":
            return {"success": False,
                    "message": f"Instance {instance_id} is not running (state: {state})"}

        ec2.reboot_instances(InstanceIds=[instance_id])

        _audit(scan_id, "REBOOT_EC2",
               f"[{account_id}] Rebooted {instance_id}. Approved by: {approved_by}. Reason: {reason}")

        return {
            "success":        True,
            "message":        f"Reboot initiated for {instance_id}",
            "instance_id":    instance_id,
            "previous_state": state,
        }
    except Exception as e:
        logger.error(f"EC2 reboot failed: {e}")
        return {"success": False, "message": str(e)}


def _scale_asg(asg, asg_name, desired_capacity, approved_by, reason, scan_id, account_id):
    """Scale an Auto Scaling Group to a higher desired capacity."""
    if not asg_name:
        return {"success": False, "message": "asg_name is required"}

    if not approved_by:
        return {"success": False,
                "message": "approved_by is required. Call escalate_to_human first."}

    if desired_capacity <= 0:
        return {"success": False, "message": "desired_capacity must be greater than 0"}

    try:
        groups = asg.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]

        if not groups:
            return {"success": False, "message": f"ASG {asg_name} not found"}

        group           = groups[0]
        current_desired = group["DesiredCapacity"]
        max_size        = group["MaxSize"]
        new_desired     = min(desired_capacity, max_size)

        if new_desired <= current_desired:
            return {
                "success":          True,
                "message":          (
                    f"ASG {asg_name} already at {current_desired} instances "
                    f"(requested: {desired_capacity}, max: {max_size})"
                ),
                "previous_desired": current_desired,
                "new_desired":      current_desired,
            }

        asg.set_desired_capacity(
            AutoScalingGroupName = asg_name,
            DesiredCapacity      = new_desired,
            HonorCooldown        = False,
        )

        _audit(scan_id, "SCALE_ASG",
               f"[{account_id}] Scaled {asg_name} from {current_desired} to {new_desired}. "
               f"Approved by: {approved_by}. Reason: {reason}")

        return {
            "success":          True,
            "message":          f"Scaled {asg_name} from {current_desired} to {new_desired}",
            "asg_name":         asg_name,
            "previous_desired": current_desired,
            "new_desired":      new_desired,
            "max_size":         max_size,
        }
    except Exception as e:
        logger.error(f"ASG scale failed: {e}")
        return {"success": False, "message": str(e)}


def _audit(scan_id, action_type, detail):
    """Write every remediation action to DynamoDB for audit trail."""
    try:
        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":     f"heal-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}",
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "agent":       "incident-agent",
            "action_type": action_type,
            "detail":      detail,
            "ttl":         int(datetime.now(timezone.utc).timestamp()) + (365 * 86400),
        })
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")
