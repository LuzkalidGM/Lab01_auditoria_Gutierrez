# Criterios de clasificación de alertas

Cinco alertas reales del reporte activo Juice Shop se asociaron a WSTG, Top 10 2021 A05 y el control A.8.9 indicado en la práctica para configuración. Es una interpretación de auditoría, no equivalencia oficial automática entre marcos ni confirmación de explotación.

- CORS: WSTG-CLNT-07. Fuente: https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side/07-Cross_Origin_Resource_Sharing
- CSP: WSTG-CONF-12, criterio indicado en la guía del curso.
- COEP, COOP y Feature-Policy obsoleto: WSTG-CONF-14 (cabeceras de seguridad). Fuente consultada el 2026-09-16: https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/14-Other_HTTP_Security_Header_Misconfigurations/

CONF-14 pertenece a la edición Latest, que puede cambiar; se identifica explícitamente esa edición. COEP/COOP deben evaluarse según la aplicación y el contexto: una cabecera ausente no implica por sí sola explotación. Las alertas informativas no se cuentan como vulnerabilidades confirmadas. Las otras correspondencias quedan pendientes para evitar asociaciones artificiales.
