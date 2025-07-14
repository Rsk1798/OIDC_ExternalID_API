// Custom Swagger UI JavaScript Enhancements

(function() {
    'use strict';

    // Wait for Swagger UI to load
    function waitForSwaggerUI() {
        if (typeof SwaggerUIBundle !== 'undefined') {
            initializeCustomFeatures();
        } else {
            setTimeout(waitForSwaggerUI, 100);
        }
    }

    function initializeCustomFeatures() {
        console.log('Initializing custom Swagger UI features...');
        
        // Add custom features after Swagger UI loads
        setTimeout(() => {
            addTokenGenerationHelper();
            addCopyTokenButton();
            addQuickTestButtons();
            addEnhancedStyling();
            addKeyboardShortcuts();
        }, 1000);
    }

    // Add token generation helper
    function addTokenGenerationHelper() {
        const authSection = document.querySelector('.auth-wrapper');
        if (!authSection) return;

        const helperDiv = document.createElement('div');
        helperDiv.className = 'token-helper';
        // The following block is commented out to disable the Quick Token Generation box:
        /*
        helperDiv.innerHTML = `
            <div style="margin: 10px 0; padding: 15px; background: #f8f9fa; border-radius: 4px; border-left: 4px solid #667eea;">
                <h4 style="margin: 0 0 10px 0; color: #3b4151;">🔑 Quick Token Generation</h4>
                <p style="margin: 0 0 10px 0; color: #555; font-size: 14px;">
                    Need a token? Use one of these endpoints:
                </p>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button onclick="generateToken('azure-ad')" style="background: #49cc90; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 12px;">
                        Generate Azure AD Token
                    </button>
                    <button onclick="generateToken('custom')" style="background: #667eea; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 12px;">
                        Generate Custom JWT
                    </button>
                </div>
            </div>
        `;
        */
        authSection.parentNode.insertBefore(helperDiv, authSection);
    }

    // Add copy token button
    function addCopyTokenButton() {
        const authorizeBtn = document.querySelector('.auth-wrapper .authorize');
        if (!authorizeBtn) return;

        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-token-btn';
        copyBtn.innerHTML = '📋 Copy Token';
        copyBtn.style.cssText = `
            background: #6c757d;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 10px;
            font-size: 12px;
        `;
        
        copyBtn.onclick = function() {
            const tokenInput = document.querySelector('.auth-wrapper input[type="text"]');
            if (tokenInput && tokenInput.value) {
                navigator.clipboard.writeText(tokenInput.value).then(() => {
                    copyBtn.innerHTML = '✅ Copied!';
                    setTimeout(() => {
                        copyBtn.innerHTML = '📋 Copy Token';
                    }, 2000);
                });
            }
        };

        authorizeBtn.parentNode.appendChild(copyBtn);
    }

    // Add quick test buttons
    function addQuickTestButtons() {
        const opblocks = document.querySelectorAll('.opblock');
        
        opblocks.forEach(opblock => {
            const summary = opblock.querySelector('.opblock-summary');
            if (!summary) return;

            const testBtn = document.createElement('button');
            testBtn.className = 'quick-test-btn';
            testBtn.innerHTML = '🧪 Quick Test';
            testBtn.style.cssText = `
                background: #ffc107;
                color: #212529;
                border: none;
                padding: 4px 8px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 11px;
                margin-left: 10px;
            `;
            
            testBtn.onclick = function(e) {
                e.stopPropagation();
                const executeBtn = opblock.querySelector('.btn.execute');
                if (executeBtn) {
                    executeBtn.click();
                }
            };

            summary.appendChild(testBtn);
        });
    }

    // Add enhanced styling
    function addEnhancedStyling() {
        const style = document.createElement('style');
        style.textContent = `
            .token-helper {
                margin: 15px 0;
            }
            
            .quick-test-btn:hover {
                background: #e0a800 !important;
                transform: translateY(-1px);
            }
            
            .copy-token-btn:hover {
                background: #5a6268 !important;
                transform: translateY(-1px);
            }
            
            .opblock-summary:hover {
                background: rgba(0,0,0,0.02);
            }
            
            .swagger-ui .opblock-description {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 4px;
                margin: 10px 0;
                border-left: 4px solid #667eea;
            }
            
            .swagger-ui .responses-wrapper {
                background: #f8f9fa;
                border-radius: 4px;
                padding: 15px;
                margin: 10px 0;
            }
            
            .swagger-ui .responses-table {
                background: white;
                border-radius: 4px;
                overflow: hidden;
            }
        `;
        document.head.appendChild(style);
    }

    // Add keyboard shortcuts
    function addKeyboardShortcuts() {
        document.addEventListener('keydown', function(e) {
            // Ctrl/Cmd + K to focus on authorization
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                const authInput = document.querySelector('.auth-wrapper input[type="text"]');
                if (authInput) {
                    authInput.focus();
                }
            }
            
            // Ctrl/Cmd + Enter to execute current operation
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const activeExecuteBtn = document.querySelector('.opblock.is-open .btn.execute');
                if (activeExecuteBtn) {
                    activeExecuteBtn.click();
                }
            }
        });
    }

    // Global functions for token generation
    window.generateToken = function(type) {
        const baseUrl = window.location.origin;
        let endpoint, requestBody;
        
        if (type === 'azure-ad') {
            endpoint = '/Token/azure-ad';
            requestBody = {
                client_id: 'your-client-id',
                client_secret: 'your-client-secret',
                scope: 'https://graph.microsoft.com/.default'
            };
        } else if (type === 'custom') {
            endpoint = '/Token';
            requestBody = new FormData();
            requestBody.append('client_id', 'your-client-id');
            requestBody.append('client_secret', 'your-client-secret');
            requestBody.append('scope', 'api://default');
            requestBody.append('grant_type', 'client_credentials');
        }
        
        // Show a modal with the request details
        showTokenGenerationModal(type, endpoint, requestBody);
    };

    function showTokenGenerationModal(type, endpoint, requestBody) {
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        `;
        
        const content = document.createElement('div');
        content.style.cssText = `
            background: white;
            padding: 30px;
            border-radius: 8px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        `;
        
        const isFormData = requestBody instanceof FormData;
        const requestBodyText = isFormData ? 
            Array.from(requestBody.entries()).map(([key, value]) => `${key}: ${value}`).join('\n') :
            JSON.stringify(requestBody, null, 2);
        
        content.innerHTML = `
            <h3 style="margin: 0 0 20px 0; color: #3b4151;">Generate ${type === 'azure-ad' ? 'Azure AD' : 'Custom JWT'} Token</h3>
            <p style="color: #555; margin-bottom: 20px;">
                Use this endpoint to generate a token, then copy the <code>access_token</code> from the response.
            </p>
            
            <div style="margin-bottom: 20px;">
                <strong>Endpoint:</strong>
                <code style="background: #f8f9fa; padding: 5px 10px; border-radius: 4px; display: block; margin-top: 5px;">
                    POST ${window.location.origin}${endpoint}
                </code>
            </div>
            
            <div style="margin-bottom: 20px;">
                <strong>Request Body:</strong>
                <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; margin-top: 5px;">${requestBodyText}</pre>
            </div>
            
            <div style="margin-bottom: 20px;">
                <strong>Steps:</strong>
                <ol style="margin: 10px 0; padding-left: 20px;">
                    <li>Update the <code>client_id</code> and <code>client_secret</code> with your actual values</li>
                    <li>Send the request to the endpoint</li>
                    <li>Copy the <code>access_token</code> from the response</li>
                    <li>Click "Authorize" in Swagger UI and paste the token</li>
                </ol>
            </div>
            
            <div style="text-align: right;">
                <button onclick="this.closest('.modal').remove()" style="background: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">
                    Close
                </button>
            </div>
        `;
        
        modal.appendChild(content);
        modal.className = 'modal';
        document.body.appendChild(modal);
        
        // Close modal when clicking outside
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                modal.remove();
            }
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', waitForSwaggerUI);
    } else {
        waitForSwaggerUI();
    }

})(); 