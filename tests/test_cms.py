from web_audit.cms import fingerprint

HEADERS = {"Content-Type": "text/html"}


def _products(body):
    return {m.product for m in fingerprint("https://example.com/", HEADERS, body.encode())}


def test_wordpress_assets_do_not_look_like_other_platforms():
    body = (
        "<link href='/wp-includes/blocks/image/style.min.css?ver=6.4.3'>"
        "<style>@font-face{src:url('/wp-content/themes/twentytwentyfour/fonts/a.woff2')}</style>"
    )
    assert _products(body) == {"WordPress"}


def test_mentioning_a_platform_in_text_is_not_a_detection():
    assert _products("<p>Why we moved from Magento and PrestaShop to a custom shop</p>") == set()


def test_real_magento_and_prestashop_markup_is_detected():
    magento = '<div data-mage-init=\'{"x":{}}\'></div><script src="/static/frontend/Luma/app.js">'
    prestashop = '<script>var prestashop = {};</script><link href="/modules/ps_shoppingcart/a.css">'
    assert _products(magento) == {"Magento"}
    assert _products(prestashop) == {"PrestaShop"}
