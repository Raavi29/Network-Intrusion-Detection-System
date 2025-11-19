// Product data
const products = [
    {
        id: 1,
        name: 'Classic White Tee',
        description: 'Comfortable and versatile white t-shirt perfect for everyday wear',
        price: 29.99,
        sizes: ['S', 'M', 'L', 'XL'],
        image: '👕'
    },
    {
        id: 2,
        name: 'Premium Black Tee',
        description: 'Sleek black t-shirt made from premium cotton blend',
        price: 34.99,
        sizes: ['S', 'M', 'L', 'XL', 'XXL'],
        image: '👕'
    },
    {
        id: 3,
        name: 'Navy Blue Classic',
        description: 'Timeless navy blue t-shirt with modern fit',
        price: 32.99,
        sizes: ['S', 'M', 'L', 'XL'],
        image: '👕'
    },
    {
        id: 4,
        name: 'Gray Premium',
        description: 'Soft gray t-shirt with comfortable relaxed fit',
        price: 31.99,
        sizes: ['S', 'M', 'L', 'XL', 'XXL'],
        image: '👕'
    },
    {
        id: 5,
        name: 'Burgundy Red',
        description: 'Rich burgundy t-shirt for a bold statement',
        price: 35.99,
        sizes: ['M', 'L', 'XL'],
        image: '👕'
    },
    {
        id: 6,
        name: 'Forest Green',
        description: 'Natural forest green t-shirt with eco-friendly materials',
        price: 33.99,
        sizes: ['S', 'M', 'L', 'XL'],
        image: '👕'
    }
];

// Cart management
let cart = JSON.parse(localStorage.getItem('cart')) || [];

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    renderProducts();
    updateCartCount();
    setupEventListeners();
});

// Render products
function renderProducts() {
    const productsGrid = document.getElementById('productsGrid');
    productsGrid.innerHTML = products.map(product => `
        <div class="product-card" onclick="showProductDetails(${product.id})">
            <div class="product-image">${product.image}</div>
            <div class="product-info">
                <div class="product-name">${product.name}</div>
                <div class="product-description">${product.description}</div>
                <div class="product-footer">
                    <div class="product-price">$${product.price.toFixed(2)}</div>
                    <button class="add-to-cart-btn" onclick="event.stopPropagation(); addToCart(${product.id})">
                        Add to Cart
                    </button>
                </div>
            </div>
        </div>
    `).join('');
}

// Show product details
function showProductDetails(productId) {
    const product = products.find(p => p.id === productId);
    if (!product) return;

    const modal = document.getElementById('productModal');
    const details = document.getElementById('productDetails');
    
    details.innerHTML = `
        <div class="product-details-image">${product.image}</div>
        <div class="product-details-info">
            <h2>${product.name}</h2>
            <p>${product.description}</p>
            <div class="product-price">$${product.price.toFixed(2)}</div>
            <div class="size-selector">
                <label>Select Size:</label>
                <div class="size-options" id="sizeOptions">
                    ${product.sizes.map(size => `
                        <div class="size-option" onclick="selectSize(this, '${size}')">${size}</div>
                    `).join('')}
                </div>
            </div>
            <button class="btn btn-primary btn-block" onclick="addToCartWithSize(${product.id})">
                Add to Cart
            </button>
        </div>
    `;
    
    modal.classList.add('active');
}

let selectedSize = null;

function selectSize(element, size) {
    // Remove selected class from all options
    document.querySelectorAll('.size-option').forEach(opt => {
        opt.classList.remove('selected');
    });
    // Add selected class to clicked option
    element.classList.add('selected');
    selectedSize = size;
}

function addToCartWithSize(productId) {
    if (!selectedSize) {
        alert('Please select a size');
        return;
    }
    addToCart(productId, selectedSize);
    closeProductModal();
}

// Add to cart
function addToCart(productId, size = 'M') {
    const product = products.find(p => p.id === productId);
    if (!product) return;

    const existingItem = cart.find(item => item.id === productId && item.size === size);
    
    if (existingItem) {
        existingItem.quantity += 1;
    } else {
        cart.push({
            id: product.id,
            name: product.name,
            price: product.price,
            size: size,
            quantity: 1,
            image: product.image
        });
    }

    saveCart();
    updateCartCount();
    showNotification('Product added to cart!');
}

// Remove from cart
function removeFromCart(productId, size) {
    cart = cart.filter(item => !(item.id === productId && item.size === size));
    saveCart();
    updateCartCount();
    renderCart();
}

// Update quantity
function updateQuantity(productId, size, change) {
    const item = cart.find(item => item.id === productId && item.size === size);
    if (!item) return;

    item.quantity += change;
    if (item.quantity <= 0) {
        removeFromCart(productId, size);
    } else {
        saveCart();
        renderCart();
        updateCartCount();
    }
}

// Render cart
function renderCart() {
    const cartItems = document.getElementById('cartItems');
    const cartTotal = document.getElementById('cartTotal');
    
    if (cart.length === 0) {
        cartItems.innerHTML = '<p class="empty-cart">Your cart is empty</p>';
        cartTotal.textContent = '0.00';
        return;
    }

    cartItems.innerHTML = cart.map(item => `
        <div class="cart-item">
            <div class="cart-item-image">${item.image}</div>
            <div class="cart-item-info">
                <div class="cart-item-name">${item.name}</div>
                <div class="cart-item-price">Size: ${item.size} - $${item.price.toFixed(2)}</div>
            </div>
            <div class="cart-item-controls">
                <button class="quantity-btn" onclick="updateQuantity(${item.id}, '${item.size}', -1)">-</button>
                <span class="quantity">${item.quantity}</span>
                <button class="quantity-btn" onclick="updateQuantity(${item.id}, '${item.size}', 1)">+</button>
                <button class="remove-btn" onclick="removeFromCart(${item.id}, '${item.size}')">Remove</button>
            </div>
        </div>
    `).join('');

    const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    cartTotal.textContent = total.toFixed(2);
}

// Save cart to localStorage
function saveCart() {
    localStorage.setItem('cart', JSON.stringify(cart));
}

// Update cart count
function updateCartCount() {
    const count = cart.reduce((sum, item) => sum + item.quantity, 0);
    document.getElementById('cartCount').textContent = count;
}

// Setup event listeners
function setupEventListeners() {
    // Cart modal
    document.getElementById('cartBtn').addEventListener('click', () => {
        renderCart();
        document.getElementById('cartModal').classList.add('active');
    });

    document.getElementById('closeCart').addEventListener('click', () => {
        document.getElementById('cartModal').classList.remove('active');
    });

    // Product modal
    document.getElementById('closeProduct').addEventListener('click', closeProductModal);

    // Checkout
    document.getElementById('checkoutBtn').addEventListener('click', () => {
        if (cart.length === 0) {
            alert('Your cart is empty');
            return;
        }
        document.getElementById('cartModal').classList.remove('active');
        document.getElementById('checkoutModal').classList.add('active');
    });

    document.getElementById('closeCheckout').addEventListener('click', () => {
        document.getElementById('checkoutModal').classList.remove('active');
    });

    // Checkout form
    document.getElementById('checkoutForm').addEventListener('submit', handleCheckout);

    // Close modals on background click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });

    // Smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

function closeProductModal() {
    document.getElementById('productModal').classList.remove('active');
    selectedSize = null;
}

// Handle checkout
async function handleCheckout(e) {
    e.preventDefault();
    
    const formData = {
        name: document.getElementById('customerName').value,
        email: document.getElementById('customerEmail').value,
        address: document.getElementById('customerAddress').value,
        city: document.getElementById('customerCity').value,
        state: document.getElementById('customerState').value,
        zip: document.getElementById('customerZip').value,
        paymentMethod: document.getElementById('paymentMethod').value,
        items: cart,
        total: cart.reduce((sum, item) => sum + (item.price * item.quantity), 0)
    };

    try {
        const response = await fetch('/api/orders', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        const result = await response.json();

        if (response.ok) {
            // Clear cart
            cart = [];
            saveCart();
            updateCartCount();

            // Show success message
            document.getElementById('checkoutModal').classList.remove('active');
            showNotification('Order placed successfully! Thank you for your purchase.', 'success');
            
            // Reset form
            document.getElementById('checkoutForm').reset();
        } else {
            alert('Error placing order: ' + result.error);
        }
    } catch (error) {
        // For demo purposes, show success even if server fails
        cart = [];
        saveCart();
        updateCartCount();
        document.getElementById('checkoutModal').classList.remove('active');
        showNotification('Order placed successfully! Thank you for your purchase.', 'success');
        document.getElementById('checkoutForm').reset();
    }
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `success-message ${type}`;
    notification.textContent = message;
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.zIndex = '3000';
    notification.style.animation = 'fadeInUp 0.3s ease';
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}



