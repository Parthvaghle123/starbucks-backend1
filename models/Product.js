const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  image: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: [
      // Menu categories
      'Bestseller',
      'Drinks',
      'Food',
      'Coffee At Home',
      'Ready to Eat',
      // Gift categories
      'Anytime',
      'Congratulations',
      'Thank You',
      'Holiday Specials'
    ]
  },
  isAvailable: {
    type: Boolean,
    default: true
  },
  featured: {
    type: Boolean,
    default: false
  },
  displayOnGift: {
    type: Boolean,
    default: false
  },
  displayOnMenu: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// Create indexes for better search performance
productSchema.index({ name: 'text', description: 'text' });
productSchema.index({ category: 1 });
productSchema.index({ isAvailable: 1 });

module.exports = mongoose.model('Product', productSchema);
