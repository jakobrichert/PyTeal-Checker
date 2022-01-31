/*===================
	JS Files  NftMarket
====================*/

(function ($) {
	"use strict";
	
// preloader
function preloader() {
	$('#preloader').delay(0).fadeOut();
};

$(window).on('load', function () {
	preloader();
});

$(document).ready(function() {
  $('.video-play-btn').magnificPopup({
	  type:'video',
	  });
	  
});

// ------------------------------------------------------------------------------ //
// Toggle Search
// ------------------------------------------------------------------------------ //
$(".header-transparent.sticky .icon-set").each(function(){  
	$("a.search", this).on("click", function(e){
		e.preventDefault();
		$(".top-search").slideToggle();
	});
});
$(".input-group-addon.close-search").on("click", function(){
	$(".top-search").slideUp();
});
			
//Mobile Menu 

/*=====| 2. Responsive Menu |=====*/

	  // main menu 
	  $('.main-menu-icon').click(function() {
		$('.menu').toggleClass('menu-open');
		$('.main-menu-icon').toggleClass('icon-cross');
		$('.menu ul').slideToggle();
		$('ul ul').css('display', 'none');
	  });
	  // Submenu
	  $('.menu ul li.has-children').click(function() {
		$(this).find('ul').slideToggle();
		$(this).siblings().find('ul').slideUp();
	  });

	  $(window).resize(function() {
		if($(window).width() > 1199) {
			$('ul').removeAttr('style');
		}
	  });



// scroll effect

$(window).on('scroll', function () {
	var scroll = $(window).scrollTop();
	if (scroll < 245) {
		$(".header-transparent").removeClass("sticky-bar");
	} else {
		$(".header-transparent").addClass("sticky-bar");
	}
});


// New Product Carousel	
$('.owl-carousel.new-proslider').owlCarousel({
    loop:false,
    margin:10,
    responsiveClass:true,
    responsive:{
        0:{
            items:1,
            nav:true
        },
        600:{
            items:1,
            nav:true
        },
        1000:{
            items:3,
            loop:false,
            nav:true			
        }
    }
});

//testimonial		
$('.owl-carousel').owlCarousel({
    loop:true,
    margin:10,
	nav:true,
    responsiveClass:true,
    responsive:{
        0:{
            items:1,
            nav:true
        },
        600:{
            items:1,
            nav:true
        },
        1000:{
            items:2,
            nav:true,
            loop:false
        }
    }
});


	 
//counter

	$('.counter_text').appear(function() {
		$('.timer').countTo();
	}, {
		accY: -100
	});

	/* ==================================================
		Contact Form Validations
	================================================== */

		$(function() {

			// Get the form.
			var form = $('#contact-form');

			// Get the messages div.
			var formMessages = $('.form-message');

			// Set up an event listener for the contact form.
			$(form).submit(function(e) {
				// Stop the browser from submitting the form.
				e.preventDefault();

				// Serialize the form data.
				var formData = $(form).serialize();

				// Submit the form using AJAX.
				$.ajax({
					type: 'POST',
					url: $(form).attr('action'),
					data: formData
				})
				.done(function(response) {
					// Make sure that the formMessages div has the 'success' class.
					$(formMessages).removeClass('error');
					$(formMessages).addClass('success');

					// Set the message text.
					$(formMessages).text(response);

					// Clear the form.
					$('#contact-form input,#contact-form textarea').val('');
				})
				.fail(function(data) {
					// Make sure that the formMessages div has the 'error' class.
					$(formMessages).removeClass('success');
					$(formMessages).addClass('error');

					// Set the message text.
					if (data.responseText !== '') {
						$(formMessages).text(data.responseText);
					} else {
						$(formMessages).text('Oops! An error occured and your message could not be sent.');
					}
				});
			});

		});		
	
// -----------------------------------------------------
	// ------------------   CURSOR    ----------------------
	// -----------------------------------------------------

	function mim_tm_cursor(){

		var myCursor	= jQuery('.mouse-cursor');

		if(myCursor.length){
			if ($("body")) {
			const e = document.querySelector(".cursor-inner"),
				t = document.querySelector(".cursor-outer");
			let n, i = 0,
				o = !1;
			window.onmousemove = function (s) {
				o || (t.style.transform = "translate(" + s.clientX + "px, " + s.clientY + "px)"), e.style.transform = "translate(" + s.clientX + "px, " + s.clientY + "px)", n = s.clientY, i = s.clientX
			}, $("body").on("mouseenter", "a, .cursor-pointer", function () {
				e.classList.add("cursor-hover"), t.classList.add("cursor-hover")
			}), $("body").on("mouseleave", "a, .cursor-pointer", function () {
				$(this).is("a") && $(this).closest(".cursor-pointer").length || (e.classList.remove("cursor-hover"), t.classList.remove("cursor-hover"))
			}), e.style.visibility = "visible", t.style.visibility = "visible"
		}
		}
	};
	mim_tm_cursor()

	/*------------------------
	   Scroll to top
	-------------------------- */
	$(function () {
			$(window).on('scroll', function(){
				if ($(this).scrollTop() > 400) {
					$('#back-to-top').fadeIn();
				} else {
					$('#back-to-top').fadeOut();
				}
			});
			});
			
	$('#back-to-top').on("click", function() {
		$('html, body').animate({scrollTop:0}, 'slow');
		return false;
	});
	

})(jQuery)	

	
	
	
	
	
	
	
	
	