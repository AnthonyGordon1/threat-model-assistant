from fastapi import APIRouter, HTTPException, Security
from app.services.auth import verify_admin_key
from app.db.pgvector import get_connection
from typing import Optional

router = APIRouter()

@router.get("/security/events")
async def get_security_events(
    limit: int = 50,
    event_type: Optional[str] = None,
    api_key: str = Security(verify_admin_key)
):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        if event_type:
            cursor.execute("""
                SELECT id, event_type, ip_address, input_text, 
                       pattern_matched, status_code, timestamp
                FROM security_events
                WHERE event_type = %s
                ORDER BY timestamp DESC
                LIMIT %s
            """, (event_type, limit))
        else:
            cursor.execute("""
                SELECT id, event_type, ip_address, input_text,
                       pattern_matched, status_code, timestamp
                FROM security_events
                ORDER BY timestamp DESC
                LIMIT %s
            """, (limit,))

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return {
            "total": len(rows),
            "events": [dict(row) for row in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/security/summary")
async def get_security_summary(api_key: str = Security(verify_admin_key)):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Total events by type
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM security_events
            GROUP BY event_type
            ORDER BY count DESC
        """)
        by_type = cursor.fetchall()

        # Top attacking IPs
        cursor.execute("""
            SELECT ip_address, COUNT(*) as attempts
            FROM security_events
            WHERE ip_address IS NOT NULL
            GROUP BY ip_address
            ORDER BY attempts DESC
            LIMIT 10
        """)
        top_ips = cursor.fetchall()

        # Most common injection patterns
        cursor.execute("""
            SELECT pattern_matched, COUNT(*) as hits
            FROM security_events
            WHERE pattern_matched IS NOT NULL
            GROUP BY pattern_matched
            ORDER BY hits DESC
        """)
        top_patterns = cursor.fetchall()

        # Events in last 24 hours
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '24 hours'
        """)
        last_24h = cursor.fetchone()

        cursor.close()
        conn.close()

        return {
            "last_24_hours": last_24h["count"],
            "by_type": [dict(row) for row in by_type],
            "top_attacking_ips": [dict(row) for row in top_ips],
            "top_injection_patterns": [dict(row) for row in top_patterns]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))