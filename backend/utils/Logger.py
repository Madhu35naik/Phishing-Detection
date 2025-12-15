# utils/Logger.py (FEEDBACK REMOVED – CLEAN VERSION)

from pymongo import MongoClient
from datetime import datetime, timezone 
import pytz
import traceback
from .config import MONGO_URI, MONGO_DATABASE_NAME, MONGO_COLLECTION_NAME, LOG_RETENTION_DAYS

# Initialize MongoDB client and collection
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[MONGO_DATABASE_NAME]
    log_collection = db[MONGO_COLLECTION_NAME]

    # Auto-delete logs after retention period
    log_collection.create_index(
        "timestamp",
        expireAfterSeconds=LOG_RETENTION_DAYS * 24 * 3600
    )

    print(f"✅ MongoDB connected to DB: {MONGO_DATABASE_NAME}")

except Exception as e:
    print(f"⚠️ MongoDB connection failed: {e}")
    client = None
    log_collection = None


# ============================================================
# LOG INDIVIDUAL OR BATCH SCAN RESULT
# ============================================================
def log_scan_result(log_data: dict, is_batch: bool = False):
    """
    Logs a single scan result or batch summary to MongoDB.
    (Feedback support removed)
    """
    if log_collection is None:
        return {"success": False, "message": "Database not connected."}

    log_data["timestamp"] = datetime.now(timezone.utc)
    log_data["is_batch"] = is_batch

    try:
        if is_batch:
            log_entry = {
                "url_count": log_data["total"],
                "summary": log_data["summary"],
                "results_preview": log_data["results"],
                "timestamp": log_data["timestamp"],
                "is_batch": True
            }
        else:
            confidence_value = log_data.get("confidence")

            log_entry = {
                "url": log_data["url"],
                "prediction": log_data["prediction"],
                "confidence": float(confidence_value) if confidence_value is not None else 0.0,
                "risk_score": log_data["risk_score"],
                "attack_types": log_data["attack_types"],
                "timestamp": log_data["timestamp"],
                "is_batch": False
            }

        result = log_collection.insert_one(log_entry)
        return {"success": True, "log_id": str(result.inserted_id)}

    except Exception as e:
        print(f"Error logging scan result: {e}")
        traceback.print_exc()
        return {"success": False, "message": str(e)}


# ============================================================
# RETRIEVE SAVED LOGS
# ============================================================
def get_scan_reports(limit: int = 50, start_date: str = None):
    """
    Retrieves recent scan logs.
    Feedback fields removed.
    """
    if log_collection is None:
        return {"error": "Database not connected."}, 500

    query = {}

    # Apply date filter if provided
    if start_date:
        try:
            dt_start_naive = datetime.strptime(start_date, "%Y-%m-%d")
            dt_start_utc = pytz.utc.localize(dt_start_naive)
            query["timestamp"] = {"$gte": dt_start_utc}
        except ValueError:
            return {"error": f"Invalid date format: {start_date}. Expected YYYY-MM-DD."}, 400
        except Exception as e:
            return {"error": f"Date filtering error: {e}"}, 500

    try:
        logs_cursor = (
            log_collection.find(query)
            .sort("timestamp", -1)
            .limit(limit)
        )

        reports = []
        for log in logs_cursor:
            log["_id"] = str(log["_id"])

            # Convert timestamp to ISO
            if isinstance(log["timestamp"], datetime):
                iso_string = log["timestamp"].isoformat()
                log["timestamp"] = iso_string.split("+")[0] + "Z"

            # Guarantee presence of confidence field
            if not log.get("is_batch", False) and "confidence" not in log:
                log["confidence"] = 0.0

            reports.append(log)

        return {"total_logs": len(reports), "reports": reports}

    except Exception as e:
        traceback.print_exc()
        return {"error": f"Database error: {e}"}, 500
