document.addEventListener('DOMContentLoaded', function() {
    // Form validation for adding a task
    const taskForm = document.querySelector('form');
    if (taskForm) {
        taskForm.addEventListener('submit', function(event) {
            const title = document.getElementById('title').value.trim();
            const assignedTo = document.getElementById('assigned_to').value;
            const dueDate = document.getElementById('due_date').value;

            if (!title) {
                alert('Task title is required.');
                event.preventDefault();
                return;
            }

            if (!assignedTo) {
                alert('Please assign the task to an employee.');
                event.preventDefault();
                return;
            }

            if (!dueDate) {
                alert('Due date is required.');
                event.preventDefault();
                return;
            }

            const today = new Date().toISOString().split('T')[0];
            if (dueDate < today) {
                alert('Due date cannot be in the past.');
                event.preventDefault();
            }
        });
    }
});