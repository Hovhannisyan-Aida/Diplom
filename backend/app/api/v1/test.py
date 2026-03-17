from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

router = APIRouter()

@router.get("/sqli", response_class=PlainTextResponse)
def vulnerable_sqli(id: str = "1"):
    """Intentionally vulnerable endpoint for SQL injection testing/demo"""
    dangerous = ["'", '"', "--", ";", "OR", "AND", "UNION", "SELECT", "SLEEP", "WAITFOR"]
    is_injected = any(d.lower() in id.lower() for d in dangerous)

    if is_injected:
        return (
            f"Warning: mysql_fetch_array() expects parameter 1 to be resource, "
            f"boolean given in /var/www/html/index.php on line 12\n"
            f"You have an error in your SQL syntax; check the manual that corresponds "
            f"to your MySQL server version for the right syntax to use near '{id}' at line 1"
        )

    return f"id: {id}, name: Test User, email: test@example.com"
