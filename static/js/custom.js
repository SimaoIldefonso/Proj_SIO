(function () {
	'use strict';

	var tinyslider = function () {
		var el = document.querySelectorAll('.testimonial-slider');

		if (el.length > 0) {
			var slider = tns({
				container: '.testimonial-slider',
				items: 1,
				axis: "horizontal",
				controlsContainer: "#testimonial-nav",
				swipeAngle: false,
				speed: 700,
				nav: true,
				controls: true,
				autoplay: true,
				autoplayHoverPause: true,
				autoplayTimeout: 3500,
				autoplayButtonOutput: false
			});
		}
	};
	tinyslider();
	function calculateTotal() {
		var precoTotals = document.querySelectorAll('#precoTotal');
		var contaTotal = 0;

		for (var i = 0; i < precoTotals.length; i++) {
			var removeItem = precoTotals[i].closest('.produtoz');
			if (removeItem.style.display !== 'none') {
				contaTotal += parseFloat(precoTotals[i].innerText.replace('€', ''));
			}
		}

		document.getElementById('contaTotal').innerText = contaTotal.toFixed(2) + '€';
	}



	function sitePlusMinus() {
		var quantityContainers = document.getElementsByClassName('quantity-container');

		function createBindings(quantityContainer) {
			var quantityAmount = quantityContainer.getElementsByClassName('quantity-amount')[0];

			var increase = quantityContainer.getElementsByClassName('increase')[0];
			var decrease = quantityContainer.getElementsByClassName('decrease')[0];

			increase.addEventListener('click', function () { atualizarPrecoTotal(quantityAmount, 1); });
			decrease.addEventListener('click', function () { atualizarPrecoTotal(quantityAmount, -1); });
			calculateTotal();
		}


		function init() {
			for (var i = 0; i < quantityContainers.length; i++) {
				createBindings(quantityContainers[i]);
				var quantityAmount = quantityContainers[i].getElementsByClassName('quantity-amount')[0];
				quantityAmount.value = quantityContainers[i].getElementsByClassName('quantity-amount')[0].name;

				var preco = parseFloat(quantityAmount.parentElement.parentElement.previousElementSibling.innerText.replace('€', ''));
				var precoTotal = quantityAmount.parentElement.parentElement.nextElementSibling;

				precoTotal.innerText = (quantityAmount.value * preco).toFixed(2) + '€'; // Atualiza o valor de 'precoTotal'

				calculateTotal();
			}
		}

		function atualizarPrecoTotal(quantityAmount, valor) {
			var value = parseInt(quantityAmount.value, 10);
			var preco = parseFloat(quantityAmount.parentElement.parentElement.previousElementSibling.innerText.replace('€', ''));
			var precoTotal = quantityAmount.parentElement.parentElement.nextElementSibling;
			var product_name = quantityAmount.parentElement.parentElement.previousElementSibling.previousElementSibling.innerText;

			if (value == 0 && valor == -1) {
				value = 0;
			} else {
				if (value >= 0 && valor == 1) {
					value += 1;
				} else if (value > 0 && valor == -1) {
					value -= 1;
				}
			}

			// Atualizar a quantidade na página
			quantityAmount.value = value;
			precoTotal.innerText = (preco * value).toFixed(2) + '€';
			calculateTotal();

			// Atualizar a quantidade no carrinho
			$.ajax({
				url: '/add_to_cart/' + product_name,
				type: 'POST',
				data: { 'quantity': value },
				success: function (response) {
					console.log(response.message);
				}
			});
		}



		init();
	}

	sitePlusMinus();

	function siteRemoveItem() {
		var removeItem = document.getElementsByClassName('produtoz');

		function createBindings(removeItem) {
			var remove = removeItem.getElementsByClassName('btn btn-black btn-sm')[0];

			remove.addEventListener('click', function () { removerItem(removeItem); });
		}

		function init() {
			for (var i = 0; i < removeItem.length; i++) {
				createBindings(removeItem[i]);

			}
		}

		function removerItem(removeItem) {
			removeItem.style.display = "none";
			calculateTotal();
		}

		init();
	}
	siteRemoveItem();




})()

