from datetime import datetime

class AuthorityEngine:

    @staticmethod
    def resolve(context: dict):
        return {
            "authority": "default-sovereign",
            "context": context,
            "timestamp": str(datetime.utcnow())
        }
