from django.conf import settings


class ContentSecurityPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        policy = getattr(settings, "CONTENT_SECURITY_POLICY", None)
        directives = policy.get("DIRECTIVES", {}) if isinstance(policy, dict) else {}
        if directives and "Content-Security-Policy" not in response:
            response["Content-Security-Policy"] = "; ".join(
                f"{name} {' '.join(values)}" for name, values in directives.items()
            )
        return response
