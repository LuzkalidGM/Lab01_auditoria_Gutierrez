\# PT03 - Contraste entre severidad CVSS y riesgo de negocio



\## Caso 1: Severidad técnica crítica y riesgo de negocio alto



El hallazgo R-001 corresponde a la aplicación legada interna y presenta

un CVSS de 10.0, clasificado técnicamente como crítico por Greenbone.



Sin embargo, al incorporar el contexto de negocio, la probabilidad fue

valorada en 4 y el impacto en 3, obteniéndose:



Riesgo inherente = 4 × 3 = 12



Por lo tanto, su nivel de riesgo de negocio es Alto y no Crítico.



Este resultado evidencia que la severidad técnica de una vulnerabilidad

no determina por sí sola el nivel de riesgo para la organización.



\## Caso 2: Severidad técnica baja y riesgo de negocio medio



El hallazgo R-006 presenta un CVSS de 2.6, correspondiente a una

severidad técnica baja. Sin embargo, afecta al Portal de clientes,

considerado un activo expuesto y con una criticidad de negocio mayor.



La probabilidad fue valorada en 2 y el impacto en 4:



Riesgo inherente = 2 × 4 = 8



El resultado corresponde a un nivel de riesgo Medio.



Este contraste demuestra que incluso una vulnerabilidad de baja

severidad técnica puede adquirir mayor relevancia cuando afecta a un

activo importante para el negocio.



\## Observación sobre los contrastes solicitados en la guía



La guía solicita localizar un caso con CVSS alto y riesgo bajo, así como

un caso con CVSS medio y riesgo crítico.



En los resultados obtenidos experimentalmente no se presentaron dichos

casos exactos. Además, aplicando la función de probabilidad indicada en

el procedimiento, un CVSS medio obtiene una probabilidad base de 2,

o como máximo 3 para un activo expuesto. Con un impacto máximo de 5,

el riesgo inherente máximo sería 15, correspondiente al nivel Alto.



Por ello, bajo los criterios y umbrales proporcionados, un CVSS medio

no puede matemáticamente alcanzar el nivel Crítico (>=20).



Se preservan los resultados obtenidos sin modificar artificialmente

los valores del escaneo o del contexto de los activos.

