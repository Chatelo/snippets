from flask import request, jsonify
from flask_restful import Resource
from flask_security import login_required, current_user
from ..models import db, ChatMessage
import random

class ChatResource(Resource):
    @login_required
    def post(self):
        """Handle chat messages"""
        try:
            data = request.get_json()
            if not data or 'message' not in data:
                return {'error': 'Message is required'}, 400
                
            user_message = data['message'].strip()
            if not user_message:
                return {'error': 'Message cannot be empty'}, 400
            
            # Simple chatbot responses (you can integrate with real AI later)
            bot_responses = [
                "That's interesting! Tell me more.",
                "I understand what you're saying.",
                "How does that make you feel?",
                "That's a great point!",
                "I'm here to help. What else would you like to know?",
                "Thanks for sharing that with me.",
                "That sounds important to you.",
                "Can you elaborate on that?",
                "I see what you mean.",
                "That's a thoughtful observation."
            ]
            
            # Generate a simple response (replace with actual AI integration)
            bot_response = self._generate_response(user_message, bot_responses)
            
            # Save to database
            chat_message = ChatMessage(
                user_id=current_user.id,
                message=user_message,
                response=bot_response
            )
            db.session.add(chat_message)
            db.session.commit()
            
            return {
                'message': user_message,
                'response': bot_response,
                'timestamp': chat_message.timestamp.isoformat()
            }, 200
            
        except Exception as e:
            db.session.rollback()
            return {'error': 'Internal server error'}, 500
    
    def _generate_response(self, message, responses):
        """Generate a simple response based on message content"""
        message_lower = message.lower()
        
        # Simple keyword-based responses
        if any(word in message_lower for word in ['hello', 'hi', 'hey']):
            return "Hello! How can I help you today?"
        elif any(word in message_lower for word in ['bye', 'goodbye', 'see you']):
            return "Goodbye! Have a great day!"
        elif any(word in message_lower for word in ['help', 'support']):
            return "I'm here to help! What do you need assistance with?"
        elif any(word in message_lower for word in ['thank', 'thanks']):
            return "You're welcome! I'm happy to help."
        elif '?' in message:
            return "That's a great question! Let me think about that..."
        else:
            return random.choice(responses)

class ChatHistoryResource(Resource):
    @login_required
    def get(self):
        """Get chat history for current user"""
        try:
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 10, type=int)
            
            messages = ChatMessage.query.filter_by(user_id=current_user.id)\
                .order_by(ChatMessage.timestamp.desc())\
                .paginate(page=page, per_page=per_page, error_out=False)
            
            return {
                'messages': [msg.to_dict() for msg in messages.items],
                'total': messages.total,
                'pages': messages.pages,
                'current_page': page
            }, 200
            
        except Exception as e:
            return {'error': 'Internal server error'}, 500
