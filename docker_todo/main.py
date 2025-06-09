from flask import Flask, render_template, request, jsonify, redirect, url_for
from datetime import datetime
import json
import os

app = Flask(__name__)

# Simple in-memory storage (you can replace with a database later)
todos = []
todo_id_counter = 1

def load_todos():
    """Load todos from file if it exists"""
    global todos, todo_id_counter
    if os.path.exists('todos.json'):
        try:
            with open('todos.json', 'r') as f:
                data = json.load(f)
                todos = data.get('todos', [])
                todo_id_counter = data.get('counter', 1)
        except (json.JSONDecodeError, KeyError, IOError):
            todos = []
            todo_id_counter = 1

def save_todos():
    """Save todos to file"""
    with open('todos.json', 'w') as f:
        json.dump({'todos': todos, 'counter': todo_id_counter}, f)

@app.route('/')
def index():
    load_todos()
    return render_template('index.html', todos=todos)

@app.route('/api/todos', methods=['GET'])
def get_todos():
    load_todos()
    return jsonify(todos)

@app.route('/api/todos', methods=['POST'])
def create_todo():
    global todo_id_counter
    load_todos()
    
    data = request.get_json()
    if not data or not data.get('title'):
        return jsonify({'error': 'Title is required'}), 400
    
    new_todo = {
        'id': todo_id_counter,
        'title': data['title'],
        'description': data.get('description', ''),
        'completed': False,
        'created_at': datetime.now().isoformat(),
        'priority': data.get('priority', 'medium')
    }
    
    todos.append(new_todo)
    todo_id_counter += 1
    save_todos()
    
    return jsonify(new_todo), 201

@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
def update_todo(todo_id):
    load_todos()
    data = request.get_json()
    
    todo = next((t for t in todos if t['id'] == todo_id), None)
    if not todo:
        return jsonify({'error': 'Todo not found'}), 404
    
    todo['title'] = data.get('title', todo['title'])
    todo['description'] = data.get('description', todo['description'])
    todo['completed'] = data.get('completed', todo['completed'])
    todo['priority'] = data.get('priority', todo['priority'])
    
    save_todos()
    return jsonify(todo)

@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
def delete_todo(todo_id):
    global todos
    load_todos()
    
    todos = [t for t in todos if t['id'] != todo_id]
    save_todos()
    
    return '', 204

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)