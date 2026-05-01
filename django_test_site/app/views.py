from django.shortcuts import render
from django.http import JsonResponse

def home(request):
    return render(request, 'home.html')

def login(request):
    message = ''
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        if username == 'admin' and password == 'admin123':
            message = 'Login successful!'
        else:
            message = 'Invalid credentials.'
    return render(request, 'login.html', {'message': message})

def search(request):
    query = request.GET.get('q', '')
    results = []
    if query:
        # Simulate some results
        results = [f'Result for: {query}', 'Article 1', 'Article 2']
    return render(request, 'search.html', {'query': query, 'results': results})

def admin_panel(request):
    return render(request, 'admin_panel.html')

def api_data(request):
    return JsonResponse({'status': 'ok', 'data': [1, 2, 3]})
