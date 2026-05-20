"""
Governance Platform — findings dashboard API.

GET /api/findings
  ?accountId=   filter by account  (uses account-agent-timestamp-index GSI)
  ?agent=       filter by agent    (uses agent-timestamp-index GSI)
  ?severity=    CRITICAL | HIGH | MEDIUM | LOW
  ?startDate=   YYYY-MM-DD
  ?endDate=     YYYY-MM-DD
  ?limit=       max results (default 100, max 500)

GET /api/findings/{scanId}
  Returns a single finding by primary key (scan_id).
"""

import json
import logging
import os

import boto3
from boto3.dynamodb.conditions import Attr, Key

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FINDINGS_TABLE  = os.environ["FINDINGS_TABLE"]
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")

dynamodb = boto3.resource("dynamodb")
table    = dynamodb.Table(FINDINGS_TABLE)


def lambda_handler(event, context):
    origin = (event.get("headers") or {}).get("origin", "")
    method = (event.get("requestContext") or {}).get("http", {}).get("method", "GET")

    if method == "OPTIONS":
        return _response(200, {}, origin)

    path_params = event.get("pathParameters") or {}
    if path_params.get("scanId"):
        return _get_finding(path_params["scanId"], origin)

    return _list_findings(event.get("queryStringParameters") or {}, origin)


def _list_findings(params, origin):
    account_id = params.get("accountId", "").strip().replace("-", "")
    agent      = params.get("agent",     "").strip()
    severity   = params.get("severity",  "").strip().upper()
    start_date = params.get("startDate", "").strip()
    end_date   = params.get("endDate",   "").strip()
    limit      = min(int(params.get("limit", "100")), 500)

    ts_start = f"{start_date}T00:00:00" if start_date else None
    ts_end   = f"{end_date}T23:59:59"   if end_date   else None

    # Build FilterExpression from non-key attributes
    filters = []
    if severity:
        filters.append(Attr("severity").eq(severity))
    if agent and account_id:
        filters.append(Attr("agent").eq(agent))

    filter_expr = None
    for f in filters:
        filter_expr = f if filter_expr is None else filter_expr & f

    try:
        if account_id:
            key_cond = Key("account_id").eq(account_id)
            if ts_start and ts_end:
                key_cond = key_cond & Key("timestamp").between(ts_start, ts_end)
            elif ts_start:
                key_cond = key_cond & Key("timestamp").gte(ts_start)
            elif ts_end:
                key_cond = key_cond & Key("timestamp").lte(ts_end)

            kwargs = {
                "IndexName":              "account-agent-timestamp-index",
                "KeyConditionExpression": key_cond,
                "ScanIndexForward":       False,
                "Limit":                  limit,
            }
            if filter_expr:
                kwargs["FilterExpression"] = filter_expr
            result = table.query(**kwargs)

        elif agent:
            key_cond = Key("agent").eq(agent)
            if ts_start and ts_end:
                key_cond = key_cond & Key("timestamp").between(ts_start, ts_end)
            elif ts_start:
                key_cond = key_cond & Key("timestamp").gte(ts_start)
            elif ts_end:
                key_cond = key_cond & Key("timestamp").lte(ts_end)

            kwargs = {
                "IndexName":              "agent-timestamp-index",
                "KeyConditionExpression": key_cond,
                "ScanIndexForward":       False,
                "Limit":                  limit,
            }
            if filter_expr:
                kwargs["FilterExpression"] = filter_expr
            result = table.query(**kwargs)

        else:
            # No key filter — table scan with optional attribute filters
            scan_filters = list(filters)
            if ts_start:
                scan_filters.append(Attr("timestamp").gte(ts_start))
            if ts_end:
                scan_filters.append(Attr("timestamp").lte(ts_end))

            kwargs = {"Limit": limit}
            if scan_filters:
                expr = scan_filters[0]
                for f in scan_filters[1:]:
                    expr = expr & f
                kwargs["FilterExpression"] = expr
            result = table.scan(**kwargs)

        items = result.get("Items", [])
        logger.info(f"Returned {len(items)} findings (account={account_id or '*'} agent={agent or '*'} severity={severity or '*'})")
        return _response(200, {"findings": items, "count": len(items)}, origin)

    except Exception:
        logger.exception("Failed to list findings")
        return _response(500, {"error": "Failed to retrieve findings"}, origin)


def _get_finding(scan_id, origin):
    try:
        result = table.get_item(Key={"scan_id": scan_id})
        item   = result.get("Item")
        if not item:
            return _response(404, {"error": "Finding not found"}, origin)
        return _response(200, item, origin)
    except Exception:
        logger.exception(f"Failed to get finding {scan_id}")
        return _response(500, {"error": "Failed to retrieve finding"}, origin)


def _response(status_code, body, origin=""):
    if "*" in ALLOWED_ORIGINS:
        allow_origin = "*"
    else:
        allow_origin = origin if origin in ALLOWED_ORIGINS else ALLOWED_ORIGINS[0]
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type":                "application/json",
            "Access-Control-Allow-Origin":  allow_origin,
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        },
        "body": json.dumps(body, default=str),
    }
