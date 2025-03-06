import os
import re

def add_cookie_consent_to_html_files():
    """
    Lägger till cookie-consent.js i alla HTML-filer i templates-mappen
    före stängande body-taggen.
    """
    templates_dir = 'templates'
    
    # Gå igenom alla filer i templates-mappen och dess undermappar
    for root, dirs, files in os.walk(templates_dir):
        for file in files:
            if file.endswith('.html'):
                file_path = os.path.join(root, file)
                
                # Läs innehållet i filen
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Kontrollera om cookie-consent.js redan finns i filen
                if "cookie-consent.js" in content:
                    print(f"Skipping {file_path} - cookie-consent.js already exists")
                    continue
                
                # Hitta lämplig plats att lägga till skriptet (före </body>)
                if "</body>" in content:
                    # Lägg till cookie-consent.js före stängande body-tagg
                    new_content = content.replace(
                        "</body>",
                        '<script src="{{ url_for(\'static\', filename=\'cookie-consent.js\') }}" defer></script>\n</body>'
                    )
                    
                    # Skriv tillbaka det uppdaterade innehållet till filen
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    print(f"Added cookie-consent.js to {file_path}")
                else:
                    print(f"Warning: Could not find </body> tag in {file_path}")

if __name__ == "__main__":
    add_cookie_consent_to_html_files()
    print("Done! Cookie consent script has been added to all HTML files.") 