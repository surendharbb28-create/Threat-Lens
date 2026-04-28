"""
ThreatLens Views
"""
import time
import json
from datetime import datetime
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .engine import scan_file, scan_url
from .db import get_db


def _serialize(doc):
    """Convert MongoDB doc to JSON-serializable dict."""
    if doc is None:
        return None
    d = dict(doc)
    if '_id' in d:
        d['_id'] = str(d['_id'])
    if 'created_at' in d and isinstance(d['created_at'], datetime):
        d['created_at'] = d['created_at'].isoformat()
    return d


# ── Pages ──────────────────────────────────────────────────────────────────────

def index(request):
    db = get_db()
    total = db['scans'].count_documents({})
    clean = db['scans'].count_documents({"threat_level": "CLEAN"})
    threats = db['scans'].count_documents({"threat_level": {"$in": ["HIGH", "CRITICAL"]}})
    recent = [_serialize(d) for d in list(db['scans'].find())[:5]]
    return render(request, 'index.html', {
        'stats': {'total': total, 'clean': clean, 'threats': threats},
        'recent_scans': recent,
    })


def history(request):
    db = get_db()
    scans = [_serialize(d) for d in db['scans'].find()]
    return render(request, 'history.html', {'scans': scans})


# ── API Endpoints ──────────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(["POST"])
def api_scan_file(request):
    if 'file' not in request.FILES:
        return JsonResponse({"error": "No file provided"}, status=400)

    uploaded = request.FILES['file']
    if uploaded.size > 50 * 1024 * 1024:  # 50MB limit
        return JsonResponse({"error": "File too large (max 50MB)"}, status=400)

    start = time.time()
    result = scan_file(uploaded, uploaded.name)
    result['scan_duration_ms'] = round((time.time() - start) * 1000)

    # Persist
    db = get_db()
    db['scans'].insert_one(dict(result))

    return JsonResponse(_serialize(result))


@csrf_exempt
@require_http_methods(["POST"])
def api_scan_url(request):
    try:
        body = json.loads(request.body)
        url = body.get('url', '').strip()
    except json.JSONDecodeError:
        url = request.POST.get('url', '').strip()

    if not url:
        return JsonResponse({"error": "No URL provided"}, status=400)

    if len(url) > 2048:
        return JsonResponse({"error": "URL too long"}, status=400)

    start = time.time()
    result = scan_url(url)
    result['scan_duration_ms'] = round((time.time() - start) * 1000)

    if 'error' in result:
        return JsonResponse(result, status=400)

    db = get_db()
    db['scans'].insert_one(dict(result))

    return JsonResponse(_serialize(result))


@require_http_methods(["GET"])
def api_stats(request):
    db = get_db()
    levels = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    breakdown = {lvl: db['scans'].count_documents({"threat_level": lvl}) for lvl in levels}
    return JsonResponse({
        "total": db['scans'].count_documents({}),
        "by_level": breakdown,
        "files": db['scans'].count_documents({"scan_type": "file"}),
        "urls": db['scans'].count_documents({"scan_type": "url"}),
    })


@require_http_methods(["GET"])
def api_history(request):
    db = get_db()
    limit = min(int(request.GET.get('limit', 20)), 100)
    scan_type = request.GET.get('type')
    query = {"scan_type": scan_type} if scan_type else {}
    scans = [_serialize(d) for d in list(db['scans'].find(query))[:limit]]
    return JsonResponse({"scans": scans, "count": len(scans)})
