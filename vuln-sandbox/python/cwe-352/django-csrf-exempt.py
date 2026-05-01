# VULNERABLE: DjangoCsrfExempt — @csrf_exempt disables CSRF protection on a view
# Rule: DjangoCsrfExemptTemplate | CWE-352 | Severity: HIGH

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
import json


@csrf_exempt  # <-- VULNERABLE: removes CSRF token requirement for this endpoint
@login_required
def update_profile(request):
    """Update the authenticated user's profile data."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    data = json.loads(request.body)
    user = request.user
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = data.get('email', user.email)
    user.save()

    return JsonResponse({'status': 'updated', 'user': user.username})
