from flask import Flask, render_template, request, send_file, session
import requests
from bs4 import BeautifulSoup
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = Flask(__name__)
# Llave secreta necesaria para activar la memoria de sesión del servidor
app.secret_key = 'cookieshield_clavesecreta_super_segura'

def ejecutar_auditoria(url):
    if not url.startswith('http'):
        url = 'https://' + url
        
    rastreadores_gordos = {
        'connect.facebook.net': 'Meta Pixel (Facebook)',
        'googletagmanager.com/gtm.js': 'Google Tag Manager',
        'google-analytics.com': 'Google Analytics',
        'analytics.google.com': 'Google Analytics (v4)',
        'analytics.tiktok.com': 'TikTok Pixel Tracker',
        'hotjar.com': 'Hotjar (Behavior Analytics)',
    }
    
    try:
        cabeceras = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        respuesta = requests.get(url, headers=cabeceras, timeout=8)
        soup = BeautifulSoup(respuesta.text, 'html.parser')
        scripts_encontrados = soup.find_all('script')
        
        peligros_detectados = []
        for script in scripts_encontrados:
            src = script.get('src', '')
            texto_interno = script.string if script.string else ''
            
            for clave, nombre in rastreadores_gordos.items():
                if clave in src or clave in texto_interno:
                    if nombre not in peligros_detectados:
                        peligros_detectados.append(nombre)
                        
        return peligros_detectados
    except Exception as e:
        return ["Error de conexión al analizar el sitio web"]

@app.route('/', methods=['GET', 'POST'])
def home():
    peligros = []
    escaneado = False
    url_introducida = ""
    
    if request.method == 'POST':
        url_introducida = request.form.get('url')
        if url_introducida:
            # Guardamos la web en la memoria del servidor antes de mostrar el resultado
            session['ultima_url'] = url_introducida
            peligros = ejecutar_auditoria(url_introducida)
            escaneado = True
            
    return render_template('index.html', peligros=peligros, escaneado=escaneado, url_introducida=url_introducida)

@app.route('/descargar-pdf')
def descargar_pdf():
    # Recuperamos la web guardada en la sesión. Si no hay ninguna, usa una por defecto.
    url_target = session.get('ultima_url', 'web-detectada.com')
    peligros = ejecutar_auditoria(url_target)
    
    # Creamos un archivo temporal en memoria para el PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    
    styles = getSampleStyleSheet()
    
    # Estilos Premium del PDF
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#12141C'), spaceAfter=6)
    subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#6366F1'), spaceAfter=20)
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=11, textColor=colors.HexColor('#2C3E50'), leading=16)
    alert_style = ParagraphStyle('AlertStyle', parent=styles['Normal'], fontSize=12, textColor=colors.HexColor('#FF4E4E'), fontWeight='Bold')
    
    # Contenido del PDF
    story.append(Paragraph("COOKIE SHIELD // Compliance Report", title_style))
    story.append(Paragraph(f"AUDITORÍA AUTOMATIZADA DE PRIVACIDAD PARA: {url_target.upper()}", subtitle_style))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph("<b>Resumen Ejecutivo:</b> Este documento certifica los hallazgos técnicos encontrados en la raíz del sitio web especificado, analizando los scripts que se ejecutan de manera automática e inconsentida, violando potencialmente las directrices de la GDPR europea y la CCPA de California.", body_style))
    story.append(Spacer(1, 15))
    
    if peligros and "Error" not in peligros[0]:
        story.append(Paragraph(f"⚠️ <b>ESTADO: NO CUMPLIMENTADO (CRÍTICO)</b><br/>Se han detectado {len(peligros)} brechas de seguridad de datos de terceros de rastreo masivo.", alert_style))
        story.append(Spacer(1, 15))
        
        # Tabla de Hallazgos
        tabla_datos = [["Script Detectado", "Gravedad", "Acción Recomendada"]]
        for p in peligros:
            tabla_datos.append([p, "ALTA (Bloqueante)", "Bloquear script hasta aceptación explícita"])
            
        t = Table(tabla_datos, colWidths=[150, 120, 240])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#12141C')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F8FAFC')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('FONTSIZE', (0,1), (-1,-1), 9),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("✅ <b>ESTADO: COMPLIANT</b><br/>No se han detectado scripts de seguimiento masivo cargándose antes del consentimiento en el HTML de entrada.", body_style))
        
    story.append(Spacer(1, 40))
    story.append(Paragraph("<font color='#9CA3AF'><i>Informe generado de manera automatizada por la infraestructura de cifrado y auditoría de CookieShield. Licencia llave en mano (Turnkey Asset comercial).</i></font>", body_style))
    
    doc.build(story)
    buffer.seek(0)
    
    return send_file(buffer, as_attachment=True, download_name=f"CookieShield_Report_{url_target}.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)