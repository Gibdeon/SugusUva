# 🎯 Taller de Evasión de Defensas - SugusUva Edition

Bienvenido/a al repositorio oficial del **Taller de Evasión de Defensas** presentado por **Javier Ferrero Rodríguez (@Gibdeon)**.

> ⚠️ **Propósito educativo únicamente.** No apoyamos el uso malicioso de las herramientas ni técnicas aquí descritas.


---

## 📁 Estructura del Repositorio

- `chisel/` -  Chisel (network tunneling) puedes descargarlo en su sitio oficial https://github.com/jpillora/chisel/releases.
- `dll_clase/` - Codigo VS para generar una dll y descifrar el payload.
- `dormido/` - Codigo Sleep para ver la inyeccion de dll en los EDR.
- `pdf/` - Documentos de las charla y taller SugusUva
- `procmon/` - Análisis con Sysinternals Procmon para visualizar carga de DLLs y comportamiento puedes descargarlo en su sitio oficial https://learn.microsoft.com/es-es/sysinternals/downloads/procmon.
- `realams/` - Prácticas relacionadas con evadir AMSI mediante dll side loading.
- `threathcheck/` - Uso de la herramienta [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck).
- `enc3.py` - Script de cifrado para payloads.
- `gen_def.py` - Generador de definiciones para dllsideloading.

---

## 📚 Contenidos del Taller

- Historia y evolución del malware.
- Tipos de defensas y mecanismos de detección.
- Técnicas de evasión:
  - Firmas estáticas
  - Análisis de memoria
  - **DLL SideLoading**
  - Loaders con shellcode
  - **Unhooking** de funciones monitorizadas

---

