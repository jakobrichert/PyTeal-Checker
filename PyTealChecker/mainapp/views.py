from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .forms import NewUserForm
from .analysis_service import get_analysis_service
import json


def index(request):
    """Main page with contract input form"""
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['input']

            # Perform comprehensive analysis
            analysis_service = get_analysis_service()
            result = analysis_service.analyze_contract(code)

            # Store result in session for display
            request.session['analysis_result'] = result.to_dict()

            # Redirect based on result
            if result.is_secure:
                return HttpResponseRedirect('/valid')
            else:
                return HttpResponseRedirect('/notvalid')
    else:
        form = NewUserForm()

    return render(request=request, template_name="mainapp/index.html", context={"form": form})


def notvalid(request):
    """Page showing insecure contract analysis"""
    analysis_result = request.session.get('analysis_result', {})
    context = {'analysis': analysis_result}
    return render(request=request, template_name="mainapp/notvalid.html", context=context)


def valid(request):
    """Page showing secure contract analysis"""
    analysis_result = request.session.get('analysis_result', {})
    context = {'analysis': analysis_result}
    return render(request=request, template_name="mainapp/valid.html", context=context)


def best(request):
    """Best practices page"""
    data = {}
    return render(request=request, template_name="mainapp/best.html", context=data)


def about(request):
    """About page"""
    data = {}
    return render(request=request, template_name="mainapp/about.html", context=data)


# REST API Endpoints

@csrf_exempt
@require_http_methods(["POST"])
def api_analyze(request):
    """
    REST API endpoint for contract analysis

    POST /api/analyze
    Body: {"code": "pyteal code here"}
    Returns: JSON with comprehensive analysis
    """
    try:
        # Parse request body
        data = json.loads(request.body)
        code = data.get('code', '')

        if not code:
            return JsonResponse({
                'error': 'No code provided',
                'message': 'Please provide PyTeal code in the "code" field'
            }, status=400)

        # Perform analysis
        analysis_service = get_analysis_service()
        result = analysis_service.analyze_contract(code)

        # Return result as JSON
        return JsonResponse({
            'success': True,
            'analysis': result.to_dict()
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON',
            'message': 'Request body must be valid JSON'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'error': 'Analysis failed',
            'message': str(e)
        }, status=500)


@require_http_methods(["GET"])
def api_health(request):
    """
    Health check endpoint

    GET /api/health
    Returns: API status
    """
    return JsonResponse({
        'status': 'healthy',
        'service': 'PyTeal-Checker API',
        'version': '2.0'
    })


@require_http_methods(["GET"])
def api_features(request):
    """
    Get list of security features analyzed

    GET /api/features
    Returns: List of security features checked
    """
    features = {
        'security_checks': [
            'Rekey vulnerability detection',
            'Close remainder vulnerability detection',
            'Fee validation',
            'Authorization checks',
            'Arithmetic safety',
            'Time manipulation resistance',
            'Randomness security',
            'Delete/Update permission validation',
            'Asset transfer validation',
            'Group transaction validation',
            'Input validation',
            'Reentrancy pattern detection'
        ],
        'ml_features': [
            'Text-based pattern recognition',
            'Feature extraction (30+ features)',
            'Ensemble classification',
            'Confidence scoring'
        ],
        'code_metrics': [
            'Lines of code',
            'Contract type detection',
            'Function count',
            'Security score (0-100)',
            'Production readiness assessment'
        ]
    }

    return JsonResponse(features)