from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import uuid

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    orders = db.relationship('Order', backref='user', lazy=True)
    cart_items = db.relationship('CartItem', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat()
        }

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    products = db.relationship('Product', backref='category', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'product_count': len(self.products)
        }

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock_quantity = db.Column(db.Integer, default=0)
    image_filename = db.Column(db.String(200))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    cart_items = db.relationship('CartItem', backref='product', lazy=True)
    order_items = db.relationship('OrderItem', backref='product', lazy=True)
    
    @property
    def image_url(self):
        if self.image_filename:
            return url_for('static', filename=f'uploads/{self.image_filename}')
        return url_for('static', filename='images/no-image.png')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'stock_quantity': self.stock_quantity,
            'image_url': self.image_url,
            'category': self.category.name if self.category else None,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def total_price(self):
        return self.quantity * self.product.price
    
    def to_dict(self):
        return {
            'id': self.id,
            'product': self.product.to_dict(),
            'quantity': self.quantity,
            'total_price': self.total_price
        }

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, confirmed, shipped, delivered, cancelled
    shipping_address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    order_items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'total_amount': self.total_amount,
            'status': self.status,
            'shipping_address': self.shipping_address,
            'created_at': self.created_at.isoformat(),
            'items': [item.to_dict() for item in self.order_items]
        }

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)  # Price at time of order
    
    @property
    def total_price(self):
        return self.quantity * self.price
    
    def to_dict(self):
        return {
            'id': self.id,
            'product_name': self.product.name,
            'quantity': self.quantity,
            'price': self.price,
            'total_price': self.total_price
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Add UUID to prevent filename conflicts
        name, ext = os.path.splitext(filename)
        filename = f"{name}_{uuid.uuid4().hex[:8]}{ext}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename
    return None

# Routes
@app.route('/')
def home():
    products = Product.query.filter_by(is_active=True).limit(8).all()
    categories = Category.query.all()
    return render_template('home.html', products=products, categories=categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Validation
        if not username or not email or not password:
            message = 'All fields are required'
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            message = 'Username already exists'
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            message = 'Email already registered'
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('register.html')
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        message = 'Registration successful! Please log in.'
        if request.is_json:
            return jsonify({'success': True, 'message': message})
        flash(message, 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            message = f'Welcome back, {user.username}!'
            if request.is_json:
                return jsonify({'success': True, 'message': message, 'redirect': next_page or url_for('home')})
            flash(message, 'success')
            return redirect(next_page or url_for('home'))
        else:
            message = 'Invalid credentials'
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 401
            flash(message, 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    category_id = request.args.get('category', type=int)
    search = request.args.get('search', '')
    
    query = Product.query.filter_by(is_active=True)
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if search:
        query = query.filter(Product.name.contains(search))
    
    products = query.paginate(page=page, per_page=12, error_out=False)
    categories = Category.query.all()
    
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({
            'products': [p.to_dict() for p in products.items],
            'has_next': products.has_next,
            'has_prev': products.has_prev,
            'page': products.page,
            'pages': products.pages
        })
    
    return render_template('products.html', products=products, categories=categories, 
                         current_category=category_id, search=search)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    related_products = Product.query.filter(
        Product.category_id == product.category_id,
        Product.id != product.id,
        Product.is_active == True
    ).limit(4).all()
    
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({
            'product': product.to_dict(),
            'related_products': [p.to_dict() for p in related_products]
        })
    
    return render_template('product_detail.html', product=product, related_products=related_products)

@app.route('/cart')
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.total_price for item in cart_items)
    
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({
            'items': [item.to_dict() for item in cart_items],
            'total': total,
            'count': len(cart_items)
        })
    
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    data = request.get_json() if request.is_json else request.form
    product_id = int(data.get('product_id'))
    quantity = int(data.get('quantity', 1))
    
    product = Product.query.get_or_404(product_id)
    
    if quantity > product.stock_quantity:
        message = 'Not enough stock available'
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Check if item already in cart
    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    
    if cart_item:
        cart_item.quantity += quantity
        if cart_item.quantity > product.stock_quantity:
            cart_item.quantity = product.stock_quantity
            message = f'Updated to maximum available quantity ({product.stock_quantity})'
        else:
            message = f'Updated {product.name} quantity in cart'
    else:
        cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
        message = f'Added {product.name} to cart'
    
    db.session.commit()
    
    # Get updated cart count
    cart_count = CartItem.query.filter_by(user_id=current_user.id).count()
    
    if request.is_json:
        return jsonify({'success': True, 'message': message, 'cart_count': cart_count})
    flash(message, 'success')
    return redirect(url_for('cart'))

@app.route('/update_cart', methods=['POST'])
@login_required
def update_cart():
    data = request.get_json() if request.is_json else request.form
    item_id = int(data.get('item_id'))
    quantity = int(data.get('quantity'))
    
    cart_item = CartItem.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
    
    if quantity <= 0:
        db.session.delete(cart_item)
        message = 'Item removed from cart'
    else:
        if quantity > cart_item.product.stock_quantity:
            quantity = cart_item.product.stock_quantity
            message = f'Updated to maximum available quantity ({quantity})'
        else:
            message = 'Cart updated'
        cart_item.quantity = quantity
    
    db.session.commit()
    
    if request.is_json:
        cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
        total = sum(item.total_price for item in cart_items)
        return jsonify({
            'success': True,
            'message': message,
            'total': total,
            'cart_count': len(cart_items)
        })
    
    flash(message, 'success')
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    cart_item = CartItem.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
    db.session.delete(cart_item)
    db.session.commit()
    
    if request.is_json:
        cart_count = CartItem.query.filter_by(user_id=current_user.id).count()
        return jsonify({'success': True, 'message': 'Item removed from cart', 'cart_count': cart_count})
    
    flash('Item removed from cart', 'success')
    return redirect(url_for('cart'))

# Admin routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('home'))
    
    # Dashboard statistics
    stats = {
        'total_users': User.query.count(),
        'total_products': Product.query.count(),
        'total_orders': Order.query.count(),
        'total_revenue': db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    }
    
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', stats=stats, recent_orders=recent_orders)

@app.route('/admin/products')
@login_required
def admin_products():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('home'))
    
    page = request.args.get('page', 1, type=int)
    products = Product.query.paginate(page=page, per_page=10, error_out=False)
    categories = Category.query.all()
    
    return render_template('admin/products.html', products=products, categories=categories)

@app.route('/admin/product/add', methods=['GET', 'POST'])
@login_required
def admin_add_product():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        stock_quantity = int(request.form.get('stock_quantity'))
        category_id = int(request.form.get('category_id')) if request.form.get('category_id') else None
        
        # Handle file upload
        image_filename = None
        if 'image' in request.files:
            image_filename = save_uploaded_file(request.files['image'])
        
        product = Product(
            name=name,
            description=description,
            price=price,
            stock_quantity=stock_quantity,
            category_id=category_id,
            image_filename=image_filename
        )
        
        db.session.add(product)
        db.session.commit()
        
        flash(f'Product "{name}" added successfully!', 'success')
        return redirect(url_for('admin_products'))
    
    categories = Category.query.all()
    return render_template('admin/add_product.html', categories=categories)

@app.route('/admin/product/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_product(product_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = float(request.form.get('price'))
        product.stock_quantity = int(request.form.get('stock_quantity'))
        product.category_id = int(request.form.get('category_id')) if request.form.get('category_id') else None
        product.is_active = 'is_active' in request.form
        
        # Handle file upload
        if 'image' in request.files and request.files['image'].filename:
            image_filename = save_uploaded_file(request.files['image'])
            if image_filename:
                product.image_filename = image_filename
        
        db.session.commit()
        
        flash(f'Product "{product.name}" updated successfully!', 'success')
        return redirect(url_for('admin_products'))
    
    categories = Category.query.all()
    return render_template('admin/edit_product.html', product=product, categories=categories)

@app.route('/admin/product/delete/<int:product_id>', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    product = Product.query.get_or_404(product_id)
    
    # Check if product has orders
    if product.order_items:
        product.is_active = False
        db.session.commit()
        message = f'Product "{product.name}" deactivated (has order history)'
    else:
        db.session.delete(product)
        db.session.commit()
        message = f'Product "{product.name}" deleted successfully'
    
    if request.is_json:
        return jsonify({'success': True, 'message': message})
    
    flash(message, 'success')
    return redirect(url_for('admin_products'))

# API Routes
@app.route('/api/products')
def api_products():
    products = Product.query.filter_by(is_active=True).all()
    return jsonify({'products': [p.to_dict() for p in products]})

@app.route('/api/product/<int:product_id>')
def api_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify({'product': product.to_dict()})

@app.route('/api/cart/count')
@login_required
def api_cart_count():
    count = CartItem.query.filter_by(user_id=current_user.id).count()
    return jsonify({'count': count})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Initialize database
# @app.before_first_request
# def create_tables():
#     db.create_all()
    
#     # Create admin user if not exists
#     if not User.query.filter_by(username='admin').first():
#         admin = User(username='admin', email='admin@example.com', is_admin=True)
#         admin.set_password('admin123')
#         db.session.add(admin)
    
#     # Create sample categories
#     if not Category.query.first():
#         categories = [
#             Category(name='Electronics', description='Electronic devices and gadgets'),
#             Category(name='Clothing', description='Fashion and apparel'),
#             Category(name='Books', description='Books and educational materials'),
#             Category(name='Home & Garden', description='Home improvement and gardening')
#         ]
#         for category in categories:
#             db.session.add(category)
    
#     db.session.commit()



if __name__ == '__main__':
     with app.app_context():
        db.create_all()
         # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
          admin = User(username='admin', email='admin@example.com', is_admin=True)
          admin.set_password('admin123')
          db.session.add(admin)
    
    # Create sample categories
        if not Category.query.first():
            categories = [
            Category(name='Electronics', description='Electronic devices and gadgets'),
            Category(name='Clothing', description='Fashion and apparel'),
            Category(name='Books', description='Books and educational materials'),
            Category(name='Home & Garden', description='Home improvement and gardening')
            ]
            for category in categories:
                db.session.add(category)
    
        db.session.commit()

app.run(debug=True)