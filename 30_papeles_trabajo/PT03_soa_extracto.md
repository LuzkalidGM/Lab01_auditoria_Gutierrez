\# PT03 - Extracto de la Declaración de Aplicabilidad (SoA)



\## Taller 03 - Evaluación y tratamiento de riesgos



La presente Declaración de Aplicabilidad parcial se elaboró a partir de

los riesgos identificados mediante Greenbone/OpenVAS y posteriormente

valorados considerando el contexto de negocio de los activos auditados.



| Control | Título | ¿Aplica? | Justificación | Estado | Riesgo que trata |

|---|---|---|---|---|---|

| A.8.8 | Management of technical vulnerabilities | Sí | Se identificaron vulnerabilidades técnicas, incluyendo un sistema operativo fuera de soporte y un aviso de seguridad de Debian. | No implementado | R-001, R-002 |

| A.8.9 | Configuration management | Sí | Se detectaron configuraciones de red que permiten divulgar información mediante TCP e ICMP Timestamps. | Parcial | R-003, R-006, R-008 |

| A.8.20 | Networks security | Sí | Los hallazgos de TCP e ICMP Timestamp evidencian la necesidad de fortalecer las configuraciones de seguridad de red de los activos. | Parcial | R-003, R-006, R-008 |

| A.8.21 | Security of network services | Sí | Los servicios de red deben configurarse para reducir la exposición innecesaria de información técnica utilizada durante actividades de reconocimiento. | Parcial | R-003, R-006, R-008 |

| A.7.4 | Physical security monitoring | No | El alcance del laboratorio corresponde a contenedores Docker y activos virtualizados, por lo que no existen instalaciones físicas bajo evaluación directa en este ejercicio. | N/A | — |



\## Justificación del tratamiento



\### A.8.8 - Management of technical vulnerabilities



Este control se considera aplicable debido a los hallazgos R-001 y

R-002. R-001 corresponde al uso de Debian GNU/Linux 9 fuera de soporte,

mientras que R-002 corresponde a un aviso de seguridad identificado en

el sistema que soporta la Base de datos ERP.



Las medidas propuestas comprenden actualización, aplicación de parches,

gestión periódica de vulnerabilidades y ejecución de nuevos análisis con

Greenbone/OpenVAS después de la remediación.



\### A.8.9 - Configuration management



Este control aplica a R-003, R-006 y R-008 debido a configuraciones de

red que permiten divulgar información mediante TCP Timestamp e ICMP

Timestamp.



Se propone establecer configuraciones base seguras, revisar parámetros

de red y validar posteriormente las modificaciones mediante un nuevo

escaneo.



\### A.8.20 - Networks security



Aplica debido a que parte de los hallazgos permiten obtener información

del sistema mediante protocolos de red. Las configuraciones de red deben

revisarse y limitarse a las funciones estrictamente necesarias para la

operación de los servicios.



\### A.8.21 - Security of network services



Aplica porque los servicios expuestos deben configurarse de manera que

no revelen información técnica innecesaria que facilite actividades de

reconocimiento por parte de un atacante.



\### A.7.4 - Physical security monitoring



Este control se excluye del alcance del ejercicio debido a que los

activos evaluados se encuentran implementados como contenedores dentro

de una infraestructura virtual de laboratorio. No se están auditando

instalaciones físicas, controles de acceso físico ni sistemas de

videovigilancia.



La exclusión se limita al alcance de este laboratorio y no implica que

el control sea innecesario para una organización real.



\## Trazabilidad



Los controles seleccionados se encuentran relacionados con los cinco

riesgos principales registrados y revisados en SimpleRisk:



\- R-001: Sistema operativo fuera de soporte en aplicación legada interna.

\- R-002: Vulnerabilidad de seguridad Debian en Base de datos ERP.

\- R-006: Divulgación de información mediante TCP Timestamps en Portal de clientes.

\- R-008: Divulgación de información mediante ICMP Timestamp en Portal de clientes.

\- R-003: Divulgación de información mediante TCP Timestamps en Base de datos ERP.



Los riesgos fueron sometidos a tratamiento y revisión en SimpleRisk,

manteniendo trazabilidad entre la evidencia técnica, el registro de

riesgos y los controles seleccionados.

