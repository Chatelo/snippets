// Chat functionality for the chatbot application

document.addEventListener('DOMContentLoaded', function() {
    const chatForm = document.getElementById('chat-form');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const messagesContainer = document.getElementById('messages-container');
    const chatMessages = document.getElementById('chat-messages');
    const historyToggle = document.getElementById('history-toggle');
    const historyModal = document.getElementById('history-modal');
    const closeHistory = document.getElementById('close-history');
    const historyContent = document.getElementById('history-content');
    
    // Auto-focus on message input
    if (messageInput) {
        messageInput.focus();
    }
    
    // Handle chat form submission
    if (chatForm) {
        chatForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const message = messageInput.value.trim();
            if (!message) return;
            
            // Disable input and button
            messageInput.disabled = true;
            sendButton.disabled = true;
            sendButton.innerHTML = '<span class="loading-dots">Sending</span>';
            
            // Add user message to chat
            addMessage(message, 'user');
            
            // Clear input
            messageInput.value = '';
            
            try {
                // Get CSRF token
                const csrfToken = document.querySelector('input[name="csrf_token"]').value;
                
                // Send message to API
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ message: message })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Add bot response to chat
                    addMessage(data.response, 'bot');
                } else {
                    addMessage('Sorry, I encountered an error. Please try again.', 'bot', true);
                }
            } catch (error) {
                console.error('Error:', error);
                addMessage('Sorry, I encountered an error. Please try again.', 'bot', true);
            } finally {
                // Re-enable input and button
                messageInput.disabled = false;
                sendButton.disabled = false;
                sendButton.innerHTML = '<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path></svg><span class="ml-2 hidden sm:inline">Send</span>';
                messageInput.focus();
            }
        });
    }
    
    // Handle Enter key in message input
    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                chatForm.dispatchEvent(new Event('submit'));
            }
        });
    }
    
    // Add message to chat interface
    function addMessage(message, sender, isError = false) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'flex items-start space-x-3 message-fade-in';
        
        const timestamp = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        
        if (sender === 'user') {
            messageDiv.innerHTML = `
                <div class="flex-1 flex justify-end">
                    <div class="max-w-xs lg:max-w-md">
                        <div class="bg-blue-600 text-white rounded-lg p-3 shadow-sm">
                            <p>${escapeHtml(message)}</p>
                        </div>
                        <p class="text-xs text-gray-500 mt-1 text-right">${timestamp}</p>
                    </div>
                </div>
                <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-gray-600 rounded-full flex items-center justify-center">
                        <svg class="h-4 w-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                        </svg>
                    </div>
                </div>
            `;
        } else {
            const bgColor = isError ? 'bg-red-50 border-red-200' : 'bg-white border-gray-200';
            const textColor = isError ? 'text-red-800' : 'text-gray-800';
            const iconColor = isError ? 'text-red-600' : 'text-blue-600';
            
            messageDiv.innerHTML = `
                <div class="flex-shrink-0">
                    <div class="w-8 h-8 ${isError ? 'bg-red-600' : 'bg-blue-600'} rounded-full flex items-center justify-center">
                        <svg class="h-4 w-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                        </svg>
                    </div>
                </div>
                <div class="flex-1">
                    <div class="${bgColor} rounded-lg p-3 shadow-sm border">
                        <p class="${textColor}">${escapeHtml(message)}</p>
                    </div>
                    <p class="text-xs text-gray-500 mt-1">${timestamp}</p>
                </div>
            `;
        }
        
        messagesContainer.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // Escape HTML to prevent XSS
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Chat history functionality
    if (historyToggle) {
        historyToggle.addEventListener('click', async function() {
            historyModal.classList.remove('hidden');
            await loadChatHistory();
        });
    }
    
    if (closeHistory) {
        closeHistory.addEventListener('click', function() {
            historyModal.classList.add('hidden');
        });
    }
    
    // Close modal when clicking outside
    if (historyModal) {
        historyModal.addEventListener('click', function(e) {
            if (e.target === historyModal) {
                historyModal.classList.add('hidden');
            }
        });
    }
    
    // Load chat history
    async function loadChatHistory() {
        try {
            historyContent.innerHTML = '<div class="text-center py-4">Loading...</div>';
            
            const response = await fetch('/api/chat/history');
            const data = await response.json();
            
            if (response.ok && data.messages.length > 0) {
                historyContent.innerHTML = '';
                data.messages.forEach(msg => {
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'border-b pb-4 mb-4 last:border-b-0';
                    messageDiv.innerHTML = `
                        <div class="space-y-2">
                            <div class="bg-blue-50 p-3 rounded">
                                <p class="font-medium text-blue-900">You:</p>
                                <p class="text-blue-800">${escapeHtml(msg.message)}</p>
                            </div>
                            ${msg.response ? `
                                <div class="bg-gray-50 p-3 rounded">
                                    <p class="font-medium text-gray-900">Bot:</p>
                                    <p class="text-gray-800">${escapeHtml(msg.response)}</p>
                                </div>
                            ` : ''}
                            <p class="text-xs text-gray-500">${new Date(msg.timestamp).toLocaleString()}</p>
                        </div>
                    `;
                    historyContent.appendChild(messageDiv);
                });
            } else {
                historyContent.innerHTML = '<div class="text-center py-4 text-gray-500">No chat history found.</div>';
            }
        } catch (error) {
            console.error('Error loading history:', error);
            historyContent.innerHTML = '<div class="text-center py-4 text-red-500">Error loading chat history.</div>';
        }
    }
});
