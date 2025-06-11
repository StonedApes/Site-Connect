{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block breadcrumb_title %}Dashboard{% endblock %}
{% block extra_head %}
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css" />
<script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
<style>
    .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
    .dashboard-card { transition: transform 0.3s ease; }
    .dashboard-card:hover { transform: translateY(-4px); }
</style>
{% endblock %}
{% block content %}
<div class="fade-in">
    <div class="mb-6 text-center">
        <h2 class="text-2xl font-bold">Welcome, {{ current_user.username }}!</h2>
        <p class="text-gray-500 dark:text-gray-400">Dashboard Overview as of <span class="dashboard-time"></span> IST</p>
        <button class="btn-primary mt-4" onclick="refreshDashboard()">Refresh Data</button>
    </div>
    <div class="dashboard-grid">
        <div class="card dashboard-card">
            <div class="card-body">
                <h4 class="mb-4">Order Status</h4>
                <div class="h-48">
                    <canvas id="orderStatusChart"></canvas>
                </div>
                <p class="text-gray-500 dark:text-gray-400 mt-2 text-sm">Total Orders: {{ status_counts|sum }}</p>
            </div>
        </div>
        <div class="card dashboard-card">
            <div class="card-body">
                <h4 class="mb-4">Incident Overview</h4>
                <div class="h-48">
                    <canvas id="incidentTypesChart"></canvas>
                </div>
                <p class="text-gray-500 dark:text-gray-400 mt-2 text-sm">Open Incidents: {{ incident_types|sum }}</p>
            </div>
        </div>
        <div class="card dashboard-card">
            <div class="card-body">
                <h4 class="mb-4">Task Progress</h4>
                <div class="h-48">
                    <canvas id="taskProgressChart"></canvas>
                </div>
                <p class="text-gray-500 dark:text-gray-400 mt-2 text-sm">Tasks Completed: {{ task_progress[0] }}</p>
            </div>
        </div>
        <div class="card dashboard-card">
            <div class="card-body">
                <h4 class="mb-4">Project Timeline</h4>
                <ul class="space-y-2">
                    {% for project in projects %}
                    <li class="flex justify-between items-center">
                        <span class="badge {{ 'bg-green-500' if project.status == 'In Progress' else 'bg-yellow-500' if project.status == 'Not Started' else 'bg-blue-500' }}">{{ project.name }}</span>
                        <span class="text-sm text-gray-500 dark:text-gray-400">{{ project.end_date }}</span>
                    </li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        <div class="card dashboard-card">
            <div class="card-body">
                <h4 class="mb-4">Weather Update</h4>
                {% for site, data in weather_data.items %}
                <p class="text-sm">{{ site }}: {{ data.temp }}°C, {{ data.condition }}</p>
                {% endfor %}
                <p class="text-gray-500 dark:text-gray-400 mt-2 text-sm">Updated: {{ current_time|strftime('%I:%M %p IST') }}</p>
            </div>
        </div>
        <div class="card dashboard-card">
            <div class="card-body">
                <h4 class="mb-4">Recent Orders</h4>
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Item</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for order in recent_orders %}
                        <tr>
                            <td>{{ order.order_id }}</td>
                            <td>{{ order.item }}</td>
                            <td><span class="badge {{ 'bg-green-500' if order.status == 'Shipped' else 'bg-yellow-500' if order.status == 'In Production' else 'bg-gray-500' }}">{{ order.status }}</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        <div class="card dashboard-card col-span-full">
            <div class="card-body">
                <h4 class="mb-4">Site Map</h4>
                <div id="site-map" class="h-96 rounded-lg"></div>
            </div>
        </div>
    </div>
</div>
{% endblock %}