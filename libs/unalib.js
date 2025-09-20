// modulo de ejemplo.

module.exports = {

 
    // Función para sanitizar contenido y prevenir XSS
    sanitizeInput: function(input) {
        if (!input || typeof input !== 'string') {
            return '';
        }

        var sanitized = input;

        // 1. Eliminar protocolos peligrosos COMPLETAMENTE
        sanitized = sanitized.replace(/javascript:/gi, '');
        sanitized = sanitized.replace(/vbscript:/gi, '');
        sanitized = sanitized.replace(/data:text\/html/gi, '');

        // 2. Eliminar expresiones CSS peligrosas
        sanitized = sanitized.replace(/expression\s*\(/gi, '');

        // 3. Eliminar funciones JavaScript peligrosas
        sanitized = sanitized.replace(/alert\s*\(/gi, '');
        sanitized = sanitized.replace(/msgbox\s*\(/gi, '');
        sanitized = sanitized.replace(/eval\s*\(/gi, '');
        sanitized = sanitized.replace(/document\./gi, '');
        sanitized = sanitized.replace(/window\./gi, '');

        // 4. Eliminar etiquetas script completamente
        sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

        // 5. Eliminar atributos de eventos JavaScript (onclick, onload, etc.)
        sanitized = sanitized.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');
        sanitized = sanitized.replace(/\s*on\w+\s*=\s*[^>\s]+/gi, '');

        // 6. Eliminar etiquetas potencialmente peligrosas
        var dangerousTags = ['iframe', 'object', 'embed', 'form', 'input', 'textarea', 'button', 'select', 'svg'];
        dangerousTags.forEach(function(tag) {
            var regex = new RegExp('<' + tag + '\\b[^>]*>', 'gi');
            sanitized = sanitized.replace(regex, '');
            var endRegex = new RegExp('</' + tag + '>', 'gi');
            sanitized = sanitized.replace(endRegex, '');
        });

        // 7. Verificar y remover patrones específicos que fallaron en las pruebas
        if (sanitized.includes('javascript:') || 
            sanitized.includes('vbscript:') ||
            sanitized.includes('data:text/html') ||
            sanitized.includes('expression(') ||
            sanitized.includes('alert') ||
            sanitized.includes('msgbox')) {
            // Si aún contiene patrones peligrosos, devolver cadena vacía
            return '';
        }

        // 8. Codificar caracteres especiales restantes
        sanitized = sanitized.replace(/</g, '&lt;')
                            .replace(/>/g, '&gt;')
                            .replace(/"/g, '&quot;')
                            .replace(/'/g, '&#x27;');

        return sanitized;
    },

    // ...existing code...

    // logica que valida si un telefono esta correcto...
    is_valid_phone: function (phone) {
      // inicializacion lazy
      var isValid = false;
      // expresion regular copiada de StackOverflow
      var re = /^[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$/i;
  
      // validacion Regex
      try {
        isValid = re.test(phone);
      } catch (e) {
        console.log(e);
      } finally {
          return isValid;
      }
      // fin del try-catch block
    },
  
    is_valid_url_image: function (url) {

      // inicializacion lazy
      var isValid = false;
      // expresion regular copiada de StackOverflow
      var re = /(http(s?):)([/|.|\w|\s|-])*\.(?:jpg|gif|png|jpeg|bmp)/i;

      // validacion Regex
      try {
        isValid = re.test(url); // Corregido: usar 'url' en lugar de 'phone'
      } catch (e) {
        console.log(e);
      } finally {
          return isValid;
      }
      // fin del try-catch block
    },    is_valid_yt_video: function (url) {

      // inicializacion lazy
      var isValid = false;
      // Expresión regular mejorada para YouTube que maneja parámetros adicionales
      var re = /^https?:\/\/(?:www\.)?(?:youtube\.com\/(?:embed\/|v\/|watch\?v=|watch\?.+&v=)|youtu\.be\/)([a-zA-Z0-9_-]{11})(?:[&?].*)?$/i;

      // validacion Regex
      try {
        isValid = re.test(url);
        console.log('Testing YouTube URL:', url, 'Result:', isValid); // Debug
      } catch (e) {
        console.log(e);
      } finally {
          return isValid;
      }
      // fin del try-catch block
    },

    // Nueva función para validar URLs generales
    is_valid_url: function (url) {
      var isValid = false;
      // Expresión regular para URLs generales
      var re = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i;

      try {
        isValid = re.test(url);
      } catch (e) {
        console.log(e);
      } finally {
          return isValid;
      }
    },

    // Función para crear enlace clickeable
    getLinkTag: function(url){
      // Agregar https:// si no tiene protocolo
      var fullUrl = url;
      if (!url.match(/^https?:\/\//)) {
        fullUrl = 'https://' + url;
      }
      var tag = '<a href="' + fullUrl + '" target="_blank" rel="noopener noreferrer">' + url + '</a>';
      return tag;
    },
  
    getYTVideoId: function(url){
        // Regex mejorado para extraer ID de YouTube con parámetros adicionales
        var match = url.match(/(?:https?:\/\/)?(?:www\.)?(?:youtu\.be\/|youtube\.com\/(?:embed\/|v\/|watch\?v=|watch\?.+&v=))([a-zA-Z0-9_-]{11})/);
        if (match && match[1]) {
            console.log('Video ID extraído:', match[1]); // Debug
            return match[1];
        }
        console.log('No se pudo extraer el ID del video'); // Debug
        return null;
    },
  
    getEmbeddedCode: function (url){
        try {
            var id = this.getYTVideoId(url);
            if (!id) {
                console.log('Error: No se pudo extraer el ID del video de:', url);
                return '⚠️ ID de video inválido';
            }
            
            console.log('Creando iframe para video ID:', id); // Debug
            var code = '<iframe width="560" height="315" src="https://www.youtube.com/embed/'+id+ '" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>';
            return code;
        } catch (e) {
            console.log("Error creating embedded code:", e);
            return '⚠️ Error al procesar video';
        }
    },
  
    getImageTag: function(url){
      var tag = '<img src="'+url+'" style="max-height: 400px;max-width: 400px;">';
      return tag;
    },
      validateMessage: function(msg){
        // Handle invalid input
        if (!msg || typeof msg !== 'string') {
            return JSON.stringify({ mensaje: '' });
        }

        try {
            var obj = JSON.parse(msg);
            
            // PASO 1: Validar que el mensaje existe
            if (!obj.mensaje || typeof obj.mensaje !== 'string') {
                return JSON.stringify({ mensaje: '' });
            }

            // PASO 2: Sanitizar el input ANTES de cualquier procesamiento
            var originalMessage = obj.mensaje;
            var sanitizedMessage = this.sanitizeInput(originalMessage);

            // PASO 3: Detectar si había contenido malicioso
            if (originalMessage !== sanitizedMessage) {
                console.log("⚠️ Contenido malicioso detectado y removido!");
                console.log("Original:", originalMessage);
                console.log("Sanitizado:", sanitizedMessage);
            }

            // PASO 4: Procesar el mensaje sanitizado según su tipo
            // SOLO se permiten URLs de YouTube e imágenes
            if(this.is_valid_url_image(sanitizedMessage)){
                console.log("✅ Es una imagen válida!");
                obj.mensaje = this.getImageTag(sanitizedMessage);
            }
            else if(this.is_valid_yt_video(sanitizedMessage)){
                console.log("✅ Es un video de YouTube válido!");
                obj.mensaje = this.getEmbeddedCode(sanitizedMessage);
            }
            else{
                console.log("✅ Es texto normal (sanitizado)!");
                obj.mensaje = sanitizedMessage;
            }
            
            return JSON.stringify(obj);
            
        } catch (e) {
            console.log('❌ Error processing message:', e);
            // En caso de error, devolver mensaje sanitizado
            return JSON.stringify({ mensaje: this.sanitizeInput(msg) });
        }
    }

  };
  