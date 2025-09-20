var val = require('../libs/unalib');
var assert = require('assert');


describe('unalib', function(){


  describe('funcion is_valid_phone', function(){

    it('deberia devolver true para 8297-8547', function(){

      assert.equal(val.is_valid_phone('8297-8547'), true);

    });

    it('deberia devolver false para 8297p-8547', function(){

      assert.equal(val.is_valid_phone('8297p-8547'), false);

    });

  });


  describe('funcion is_valid_url_image', function(){

    it('deberia devolver true para http://image.com/image.jpg', function(){

      assert.equal(val.is_valid_url_image('http://image.com/image.jpg'), true);

    });

    it('deberia devolver true para http://image.com/image.gif', function(){

      assert.equal(val.is_valid_url_image('http://image.com/image.gif'), true);

    });
    
  });

  describe('funcion is_valid_yt_video', function(){

    it('deberia devolver true para http://image.com/image.jpg', function(){

      assert.equal(val.is_valid_yt_video('https://www.youtube.com/watch?v=qYwlqx-JLok'), true);

    });

  });

  // ============================================
  // 🛡️ PRUEBAS DE PREVENCIÓN DE INYECCIÓN XSS
  // ============================================
  describe('Prevención de Inyección de Scripts', function(){

    describe('Sanitización de entrada básica', function(){
      
      it('debería remover etiquetas <script>', function(){
        var maliciousInput = '<script>alert("XSS")</script>';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('<script>'), false);
        assert.equal(result.mensaje.includes('alert'), false);
      });

      it('debería remover atributos onerror maliciosos', function(){
        var maliciousInput = '<img src="x" onerror="alert(\'XSS\')">';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('onerror'), false);
        assert.equal(result.mensaje.includes('alert'), false);
      });

      it('debería bloquear javascript: URLs', function(){
        var maliciousInput = 'javascript:alert("XSS")';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('javascript:'), false);
        assert.equal(result.mensaje.includes('alert'), false);
      });

    });

    describe('Vectores de ataque XSS avanzados', function(){

      it('debería bloquear iframes maliciosos', function(){
        var maliciousInput = '<iframe src="javascript:alert(\'XSS\')"></iframe>';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('<iframe'), false);
        assert.equal(result.mensaje.includes('javascript:'), false);
      });

      it('debería remover eventos onload en SVG', function(){
        var maliciousInput = '<svg onload="alert(\'XSS\')"></svg>';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('onload'), false);
        assert.equal(result.mensaje.includes('<svg'), false);
      });

      it('debería bloquear eventos onclick', function(){
        var maliciousInput = '<div onclick="alert(\'XSS\')">Click me</div>';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('onclick'), false);
        assert.equal(result.mensaje.includes('<div'), false);
      });

      it('debería remover etiquetas object maliciosas', function(){
        var maliciousInput = '<object data="javascript:alert(\'XSS\')"></object>';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('<object'), false);
        assert.equal(result.mensaje.includes('javascript:'), false);
      });

    });

    describe('Caracteres especiales y encoding', function(){

      it('debería sanitizar caracteres < y >', function(){
        var maliciousInput = '<script>var x = 1 > 0;</script>';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        // Los caracteres < y > deben ser codificados o removidos
        assert.equal(result.mensaje.includes('<script>'), false);
      });

      it('debería manejar comillas dobles y simples maliciosas', function(){
        var maliciousInput = 'onmouseover="alert(\'XSS\')" onmouseout="alert(\"XSS2\")"';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('onmouseover'), false);
        assert.equal(result.mensaje.includes('alert'), false);
      });

    });

    describe('Casos edge de XSS', function(){

      it('debería bloquear data URLs con javascript', function(){
        var maliciousInput = '<img src="data:text/html,<script>alert(\'XSS\')</script>">';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('data:text/html'), false);
        assert.equal(result.mensaje.includes('<script>'), false);
      });

      it('debería remover style con expression()', function(){
        var maliciousInput = '<div style="background:expression(alert(\'XSS\'))">Test</div>';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('expression'), false);
        assert.equal(result.mensaje.includes('alert'), false);
      });

      it('debería bloquear vbscript URLs', function(){
        var maliciousInput = '<img src="vbscript:msgbox(\'XSS\')">';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: maliciousInput})));
        assert.equal(result.mensaje.includes('vbscript:'), false);
        assert.equal(result.mensaje.includes('msgbox'), false);
      });

    });

    describe('Validación de contenido legítimo', function(){

      it('debería permitir texto normal sin modificación', function(){
        var normalText = 'Hola, este es un mensaje normal';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: normalText})));
        assert.equal(result.mensaje, normalText);
      });

      it('debería permitir URLs de imágenes válidas', function(){
        var imageUrl = 'https://example.com/image.jpg';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: imageUrl})));
        assert.equal(result.mensaje.includes('<img'), true);
        assert.equal(result.mensaje.includes(imageUrl), true);
      });

      it('debería permitir URLs de YouTube válidas', function(){
        var youtubeUrl = 'https://www.youtube.com/watch?v=72UO0v5ESUo';
        var result = JSON.parse(val.validateMessage(JSON.stringify({mensaje: youtubeUrl})));
        assert.equal(result.mensaje.includes('<iframe'), true);
        assert.equal(result.mensaje.includes('youtube.com/embed'), true);
      });

    });

  });

});