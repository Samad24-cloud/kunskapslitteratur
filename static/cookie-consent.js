// Cookie Consent Banner för Kunskapslitteratur
document.addEventListener('DOMContentLoaded', function() {
    // Kontrollera om användaren redan har gett samtycke
    if (!localStorage.getItem('cookieConsent')) {
        // Skapa cookie banner element
        const cookieBanner = document.createElement('div');
        cookieBanner.id = 'cookie-consent-banner';
        cookieBanner.className = 'cookie-banner';
        cookieBanner.innerHTML = `
            <div class="cookie-content">
                <div class="cookie-text">
                    <h4>Vi använder cookies</h4>
                    <p>Vi använder cookies för att förbättra din upplevelse, hantera inloggningar och sessioner, samt för att skydda mot CSRF-attacker. 
                    Genom att klicka på "Acceptera" godkänner du vår användning av cookies enligt vår <a href="/Integritetspolicy">Integritetspolicy</a>.</p>
                </div>
                <div class="cookie-buttons">
                    <button id="cookie-accept" class="btn btn-primary">Acceptera alla</button>
                    <button id="cookie-necessary" class="btn btn-outline-secondary">Endast nödvändiga</button>
                    <button id="cookie-more-info" class="btn btn-link">Mer information</button>
                </div>
            </div>
        `;
        
        // Lägg till banner i body
        document.body.appendChild(cookieBanner);
        
        // Lägg till stilar för cookie banner
        const style = document.createElement('style');
        style.textContent = `
            .cookie-banner {
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                background-color: #fff;
                box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.1);
                z-index: 1000;
                padding: 15px;
                border-top: 1px solid #e9e9e9;
            }
            
            .cookie-content {
                max-width: 1200px;
                margin: 0 auto;
                display: flex;
                flex-wrap: wrap;
                align-items: center;
                justify-content: space-between;
            }
            
            .cookie-text {
                flex: 1;
                min-width: 280px;
                padding-right: 20px;
            }
            
            .cookie-text h4 {
                margin-top: 0;
                margin-bottom: 10px;
            }
            
            .cookie-text p {
                margin-bottom: 0;
                font-size: 14px;
            }
            
            .cookie-buttons {
                display: flex;
                gap: 10px;
                margin-top: 10px;
                flex-wrap: wrap;
            }
            
            @media (max-width: 768px) {
                .cookie-content {
                    flex-direction: column;
                }
                
                .cookie-text {
                    padding-right: 0;
                    margin-bottom: 15px;
                }
            }
        `;
        
        document.head.appendChild(style);
        
        // Hantera klick på acceptera alla-knappen
        document.getElementById('cookie-accept').addEventListener('click', function() {
            // Spara samtycke i localStorage (alla cookies)
            localStorage.setItem('cookieConsent', 'all');
            localStorage.setItem('cookieConsentTimestamp', new Date().toISOString());
            
            // Dölj banner
            cookieBanner.style.display = 'none';
        });
        
        // Hantera klick på endast nödvändiga-knappen
        document.getElementById('cookie-necessary').addEventListener('click', function() {
            // Spara samtycke i localStorage (endast nödvändiga cookies)
            localStorage.setItem('cookieConsent', 'necessary');
            localStorage.setItem('cookieConsentTimestamp', new Date().toISOString());
            
            // Dölj banner
            cookieBanner.style.display = 'none';
        });
        
        // Hantera klick på mer information-knappen
        document.getElementById('cookie-more-info').addEventListener('click', function() {
            // Navigera till integritetspolicy-sidan
            window.location.href = '/Integritetspolicy';
        });
    }
}); 