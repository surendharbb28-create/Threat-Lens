
import os
from datetime import datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

_client = None
_db = None


def get_db():
    """Get or create MongoDB connection."""
    global _client, _db
    if _db is not None:
        return _db

    uri = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
    db_name = os.environ.get('MONGODB_DB', 'threatlens')

    try:
        _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        _client.admin.command('ping')  # Verify connection
        _db = _client[db_name]
        _ensure_indexes(_db)
        print(f"[ThreatLens] Connected to MongoDB: {db_name}")
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        print(f"[ThreatLens] MongoDB unavailable, using in-memory fallback: {e}")
        _db = InMemoryDB()

    return _db


def _ensure_indexes(db):
    """Create indexes for performance."""
    db.scans.create_index([("created_at", -1)])
    db.scans.create_index([("scan_type", 1)])
    db.scans.create_index([("threat_level", 1)])


class InMemoryDB:
    """Fallback in-memory store when MongoDB is unavailable."""

    def __init__(self):
        self._store = {"scans": [], "stats": []}

    def __getitem__(self, name):
        return InMemoryCollection(self._store.setdefault(name, []))

    def __getattr__(self, name):
        return InMemoryCollection(self._store.setdefault(name, []))


class InMemoryCollection:
    """Simple in-memory collection mimicking pymongo interface."""

    def __init__(self, data):
        self._data = data
        self._counter = 0

    def insert_one(self, doc):
        import uuid
        doc["_id"] = str(uuid.uuid4())
        doc.setdefault("created_at", datetime.utcnow())
        self._data.append(doc)

        class Result:
            inserted_id = doc["_id"]

        return Result()

    def find(self, query=None, **kwargs):
        results = list(self._data)
        if query:
            results = [d for d in results if self._match(d, query)]
        return iter(sorted(results, key=lambda x: x.get("created_at", datetime.min), reverse=True))

    def find_one(self, query=None):
        for doc in self.find(query):
            return doc
        return None

    def count_documents(self, query=None):
        if not query:
            return len(self._data)
        return sum(1 for d in self._data if self._match(d, query))

    def _match(self, doc, query):
        for k, v in query.items():
            if isinstance(v, dict):
                if "$in" in v and doc.get(k) not in v["$in"]:
                    return False
            elif doc.get(k) != v:
                return False
        return True

    def create_index(self, *args, **kwargs):
        pass  # No-op for in-memory
