/**
 * Session Manager - Hanterar WebSocket-anslutningar och realtidsutloggning
 */
document.addEventListener('DOMContentLoaded', function() {
    // Kontrollera om användaren är inloggad genom att leta efter en specifik meta-tagg
    const userIdMeta = document.querySelector('meta[name="user-id"]');
    if (!userIdMeta) {
        console.debug('Användaren är inte inloggad, WebSocket-anslutning behövs inte');
        return;
    }

    // Ladda Socket.IO-biblioteket dynamiskt
    const script = document.createElement('script');
    script.src = 'https://cdn.socket.io/4.6.0/socket.io.min.js';
    script.integrity = 'sha384-c79GN5VsunZvi+Q/WObgk2in0CbZsHnjEqvFxC5DxHn9lTfNce2WW6h2pH6u/kF+';
    script.crossOrigin = 'anonymous';
    
    script.onload = function() {
        initializeSocketConnection();
    };
    
    script.onerror = function() {
        console.error('Kunde inte ladda Socket.IO-biblioteket');
    };
    
    document.head.appendChild(script);
    
    function initializeSocketConnection() {
        // Skapa en WebSocket-anslutning
        const socket = io();
        
        // Lyssna på force_logout-händelser
        socket.on('force_logout', function(data) {
            console.log('Tvingad utloggning:', data.message);
            
            // Visa ett meddelande till användaren
            showLogoutMessage(data.message);
            
            // Omdirigera till inloggningssidan efter en kort fördröjning
            setTimeout(function() {
                window.location.href = '/loggain';
            }, 3000);
        });
        
        // Hantera anslutningsfel
        socket.on('connect_error', function(error) {
            console.error('WebSocket-anslutningsfel:', error);
        });
        
        // Hantera frånkoppling
        socket.on('disconnect', function(reason) {
            console.log('WebSocket frånkopplad:', reason);
            
            // Försök återansluta om det inte var en avsiktlig frånkoppling
            if (reason !== 'io client disconnect') {
                setTimeout(function() {
                    socket.connect();
                }, 5000);
            }
        });
        
        console.log('WebSocket-anslutning initierad');
    }
    
    function showLogoutMessage(message) {
        // Skapa ett meddelande-element
        const messageContainer = document.createElement('div');
        messageContainer.className = 'logout-message-container';
        messageContainer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.7);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        `;
        
        const messageBox = document.createElement('div');
        messageBox.className = 'logout-message-box';
        messageBox.style.cssText = `
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            max-width: 400px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        `;
        
        const icon = document.createElement('i');
        icon.className = 'bi bi-exclamation-triangle-fill';
        icon.style.cssText = `
            font-size: 48px;
            color: #dc3545;
            margin-bottom: 20px;
            display: block;
        `;
        
        const title = document.createElement('h4');
        title.textContent = 'Du har loggats ut';
        title.style.cssText = `
            margin-bottom: 15px;
            color: #333;
        `;
        
        const text = document.createElement('p');
        text.textContent = message;
        text.style.cssText = `
            margin-bottom: 20px;
            color: #555;
        `;
        
        const redirectText = document.createElement('p');
        redirectText.textContent = 'Du kommer att omdirigeras till inloggningssidan...';
        redirectText.style.cssText = `
            font-size: 14px;
            color: #777;
        `;
        
        messageBox.appendChild(icon);
        messageBox.appendChild(title);
        messageBox.appendChild(text);
        messageBox.appendChild(redirectText);
        messageContainer.appendChild(messageBox);
        
        document.body.appendChild(messageContainer);
    }
}); 