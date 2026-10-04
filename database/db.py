"""
MongoDB Atlas connection layer.
All other modules talk to the database ONLY through this file — nothing
else should import pymongo directly. That keeps the schema in one place.
"""
from datetime import datetime, timezone
from bson.objectid import ObjectId
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

import config
from auth.auth_manager import hash_password  # no circular import: auth_manager never imports database.db


class Database:
    _instance = None

    def __init__(self):
        try:
            # tz_aware=True is important: without it, PyMongo hands back
            # *naive* datetimes for everything read from Mongo, while the
            # rest of the app compares against datetime.now(timezone.utc)
            # (tz-aware) — mixing the two raises
            # "TypeError: can't compare offset-naive and offset-aware
            # datetimes" (this bit OTP expiry checks specifically, but the
            # same mismatch could hit any stored date). Setting this once
            # here fixes it everywhere, not just in one call site.
            self.client = MongoClient(
                config.MONGODB_URI, serverSelectionTimeoutMS=8000, tz_aware=True,
            )
            self.client.admin.command("ping")  # fail fast if URI/creds are wrong
        except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
            raise ConnectionError(
                f"Could not connect to MongoDB Atlas. Check MONGODB_URI in your .env file.\n{exc}"
            )

        self.db = self.client[config.DB_NAME]
        self.users = self.db["users"]
        self.scans = self.db["scans"]
        self.subscriptions = self.db["subscriptions"]
        self.payments = self.db["payments"]
        self.admins = self.db["admins"]
        self.otp_codes = self.db["otp_codes"]

        self._ensure_indexes()
        self._ensure_admin_seeded()

    @classmethod
    def instance(cls):
        """Simple singleton so we open one connection pool for the app's lifetime."""
        if cls._instance is None:
            cls._instance = Database()
        return cls._instance

    def _ensure_indexes(self):
        self.users.create_index("username", unique=True)
        self.users.create_index("email", unique=True)
        self.scans.create_index([("user_id", 1), ("created_at", DESCENDING)])
        self.subscriptions.create_index([("user_id", 1), ("created_at", DESCENDING)])
        self.payments.create_index([("user_id", 1), ("created_at", DESCENDING)])
        self.admins.create_index("username", unique=True)
        self.otp_codes.create_index([("email", 1), ("purpose", 1), ("created_at", DESCENDING)])
        self.otp_codes.create_index("expires_at", expireAfterSeconds=0)  # auto-cleanup expired codes

    def _ensure_admin_seeded(self):
        """
        Creates exactly one admin account the first time the app connects to
        a fresh database, using ADMIN_USERNAME/ADMIN_PASSWORD/ADMIN_EMAIL
        from .env. Does nothing if an admin already exists, or if
        ADMIN_PASSWORD hasn't been set (so no default password ever ships).
        """
        if self.admins.count_documents({}) > 0:
            return
        if not config.ADMIN_PASSWORD:
            print(f"[{config.APP_NAME}] No admin account yet, and ADMIN_PASSWORD is not set in .env — "
                  "set ADMIN_USERNAME / ADMIN_PASSWORD / ADMIN_EMAIL and restart to create the admin account.")
            return
        self.admins.insert_one({
            "username": config.ADMIN_USERNAME,
            "email": config.ADMIN_EMAIL,
            "password_hash": hash_password(config.ADMIN_PASSWORD),
            "created_at": datetime.now(timezone.utc),
        })
        print(f"[{config.APP_NAME}] Admin account '{config.ADMIN_USERNAME}' created.")

    # ------------------------------------------------------------------ #
    # Users
    # ------------------------------------------------------------------ #
    def create_user(self, username, email, password_hash, full_name=""):
        doc = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "full_name": full_name,
            "created_at": datetime.now(timezone.utc),
            "plan": "free",
            "plan_expires_at": None,
            "scans_used_this_period": 0,
            "usage_period_start": datetime.now(timezone.utc),
            "email_verified": False,
        }
        result = self.users.insert_one(doc)
        return str(result.inserted_id)

    def get_user_by_username(self, username):
        return self.users.find_one({"username": username})

    def get_user_by_email(self, email):
        return self.users.find_one({"email": email.strip().lower()})

    def get_user_by_id(self, user_id):
        return self.users.find_one({"_id": ObjectId(user_id)})

    def get_all_users(self):
        return list(self.users.find({}).sort("created_at", DESCENDING))

    def delete_user(self, user_id):
        """
        Permanently removes a user and cascades to everything tied to them
        (scans, subscriptions, payments, any pending OTP codes) so deleting
        an account doesn't leave orphaned data behind — used by the admin
        user-management screen. This does not touch Firebase/MongoDB auth
        sessions already in memory elsewhere; if that user is currently
        logged in on another device, their session simply stops working
        next time they try to do something that hits the database.
        """
        user = self.get_user_by_id(user_id)
        if not user:
            return
        oid = ObjectId(user_id)
        self.scans.delete_many({"user_id": oid})
        self.subscriptions.delete_many({"user_id": oid})
        self.payments.delete_many({"user_id": oid})
        self.otp_codes.delete_many({"email": user.get("email", "")})
        self.users.delete_one({"_id": oid})

    def update_user_profile(self, user_id, updates: dict):
        self.users.update_one({"_id": ObjectId(user_id)}, {"$set": updates})

    def set_user_email_verified(self, email):
        self.users.update_one({"email": email.strip().lower()}, {"$set": {"email_verified": True}})

    def update_user_password_by_email(self, email, new_password_hash):
        self.users.update_one({"email": email.strip().lower()}, {"$set": {"password_hash": new_password_hash}})

    def set_user_plan(self, user_id, plan, expires_at=None):
        self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"plan": plan, "plan_expires_at": expires_at}},
        )

    def increment_scan_usage(self, user_id):
        self.users.update_one({"_id": ObjectId(user_id)}, {"$inc": {"scans_used_this_period": 1}})

    def reset_scan_usage(self, user_id):
        self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"scans_used_this_period": 0, "usage_period_start": datetime.now(timezone.utc)}},
        )

    # ------------------------------------------------------------------ #
    # Scans
    # ------------------------------------------------------------------ #
    def save_scan(self, user_id, scan_type, target, results: dict, duration_seconds: float):
        doc = {
            "user_id": ObjectId(user_id),
            "scan_type": scan_type,      # "port_scan" | "vuln_scan"
            "target": target,
            "results": results,
            "duration_seconds": duration_seconds,
            "created_at": datetime.now(timezone.utc),
        }
        result = self.scans.insert_one(doc)
        return str(result.inserted_id)

    def get_scans_for_user(self, user_id, limit=None):
        cursor = self.scans.find({"user_id": ObjectId(user_id)}).sort("created_at", DESCENDING)
        if limit:
            cursor = cursor.limit(limit)
        return list(cursor)

    def get_all_scans(self):
        """Return all scans for admin-only analytics pages."""
        return list(self.scans.find({}).sort("created_at", DESCENDING))

    def get_scan_by_id(self, scan_id):
        return self.scans.find_one({"_id": ObjectId(scan_id)})

    def delete_scan(self, scan_id, user_id):
        return self.scans.delete_one({"_id": ObjectId(scan_id), "user_id": ObjectId(user_id)})

    # ------------------------------------------------------------------ #
    # Subscriptions
    # ------------------------------------------------------------------ #
    def create_subscription_record(self, user_id, plan, payment_id, start_date, end_date, billing_cycle=None):
        doc = {
            "user_id": ObjectId(user_id),
            "plan": plan,
            "billing_cycle": billing_cycle,   # "monthly" | "yearly" | None
            "payment_id": ObjectId(payment_id) if payment_id else None,
            "start_date": start_date,
            "end_date": end_date,
            "status": "active",
            "created_at": datetime.now(timezone.utc),
        }
        result = self.subscriptions.insert_one(doc)
        return str(result.inserted_id)

    def get_subscription_history(self, user_id):
        return list(self.subscriptions.find({"user_id": ObjectId(user_id)}).sort("created_at", DESCENDING))

    def has_yearly_pro_access(self, user_id):
        """Return True only for an active, unexpired yearly Pro subscription."""
        now = datetime.now(timezone.utc)
        return self.subscriptions.find_one({
            "user_id": ObjectId(user_id),
            "plan": "pro",
            "billing_cycle": "yearly",
            "status": "active",
            "end_date": {"$gt": now},
        }) is not None

    def cancel_active_subscriptions(self, user_id):
        self.subscriptions.update_many(
            {"user_id": ObjectId(user_id), "status": "active"},
            {"$set": {"status": "cancelled"}},
        )

    # ------------------------------------------------------------------ #
    # Payments (dummy / Easebuzz / Razorpay records)
    # ------------------------------------------------------------------ #
    def save_payment(self, user_id, amount, currency, status, plan_purchased,
                      gateway="mock", transaction_id=None, card_last4=None, billing_cycle=None):
        doc = {
            "user_id": ObjectId(user_id),
            "amount": amount,
            "currency": currency,
            "card_last4": card_last4,
            "status": status,          # "success" | "failed"
            "gateway": gateway,        # "mock" | "easebuzz" | "razorpay"
            "billing_cycle": billing_cycle,  # "monthly" | "yearly" | None
            "transaction_id": transaction_id or f"txn_{ObjectId()}",
            "plan_purchased": plan_purchased,
            "created_at": datetime.now(timezone.utc),
        }
        result = self.payments.insert_one(doc)
        return str(result.inserted_id)

    def get_payment_history(self, user_id):
        return list(self.payments.find({"user_id": ObjectId(user_id)}).sort("created_at", DESCENDING))

    # ------------------------------------------------------------------ #
    # Admin
    # ------------------------------------------------------------------ #
    def get_admin_by_username(self, username):
        return self.admins.find_one({"username": username})

    def get_admin_overview(self):
        """
        Aggregates everything the admin dashboard needs: user/plan counts,
        scan counts, vulnerability grade distribution, and a rough
        port-risk breakdown across every stored scan. Computed in plain
        Python rather than a Mongo aggregation pipeline so it's easy to
        read, audit, and extend.
        """
        total_users = self.users.count_documents({})
        verified_users = self.users.count_documents({"email_verified": True})
        free_users = self.users.count_documents({"plan": "free"})
        pro_users = self.users.count_documents({"plan": "pro"})

        all_scans = list(self.scans.find({}))
        port_scans = [s for s in all_scans if s.get("scan_type") == "port_scan"]
        vuln_scans = [s for s in all_scans if s.get("scan_type") == "vuln_scan"]

        grade_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        vulnerable_sites, healthy_sites = set(), set()
        for s in vuln_scans:
            grade = s.get("results", {}).get("grade")
            if grade in grade_counts:
                grade_counts[grade] += 1
            target = s.get("target")
            if grade in ("D", "F"):
                vulnerable_sites.add(target)
            elif grade in ("A", "B"):
                healthy_sites.add(target)

        high_risk_ports = {21, 23, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
        medium_risk_ports = {25, 53, 80, 110, 143, 8080}
        port_risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for s in port_scans:
            for p in s.get("results", {}).get("open_ports", []):
                port = p.get("port")
                if port in high_risk_ports:
                    port_risk_counts["HIGH"] += 1
                elif port in medium_risk_ports:
                    port_risk_counts["MEDIUM"] += 1
                else:
                    port_risk_counts["LOW"] += 1

        return {
            "total_users": total_users,
            "verified_users": verified_users,
            "free_users": free_users,
            "pro_users": pro_users,
            "total_scans": len(all_scans),
            "port_scan_count": len(port_scans),
            "vuln_scan_count": len(vuln_scans),
            "grade_counts": grade_counts,
            "vulnerable_site_count": len(vulnerable_sites),
            "healthy_site_count": len(healthy_sites),
            "port_risk_counts": port_risk_counts,
        }

    # ------------------------------------------------------------------ #
    # OTP codes (email verification + password reset)
    # ------------------------------------------------------------------ #
    def create_otp(self, email, otp_hash, purpose, created_at, expires_at):
        self.otp_codes.update_many(
            {"email": email, "purpose": purpose, "used": False},
            {"$set": {"used": True}},
        )
        self.otp_codes.insert_one({
            "email": email,
            "otp_hash": otp_hash,
            "purpose": purpose,          # "verify_email" | "reset_password"
            "created_at": created_at,
            "expires_at": expires_at,
            "used": False,
            "attempts": 0,
        })

    def get_latest_otp(self, email, purpose):
        return self.otp_codes.find_one({"email": email, "purpose": purpose}, sort=[("created_at", DESCENDING)])

    def increment_otp_attempts(self, otp_id):
        self.otp_codes.update_one({"_id": otp_id}, {"$inc": {"attempts": 1}})

    def mark_otp_used(self, otp_id):
        self.otp_codes.update_one({"_id": otp_id}, {"$set": {"used": True}})
