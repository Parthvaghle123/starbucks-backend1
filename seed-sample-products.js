const mongoose = require('mongoose');
const Product = require('./models/Product');

// MongoDB connection string
const MONGODB_URI = 'mongodb://localhost:27017/starbucks';

// Sample products data
const sampleProducts = [
  {
    name: "Iced Belgium Chocolate Latte",
    description: "Espresso with decadent Belgian chocolate sauce, mocha sauce, and steamed milk, served over ice.",
    price: 472,
    image: "https://starbucksstatic.cognizantorderserv.com/Items/Small/113849.png",
    category: "Drinks",
    isAvailable: true,
    stock: 15,
    featured: true,
    displayOnGift: false,
    displayOnMenu: true
  },
  {
    name: "Classic Hot Coffee",
    description: "Savour our premium coffee made with top 3% Arabica beans in a classic hot brew.",
    price: 157,
    image: "https://starbucksstatic.cognizantorderserv.com/Items/Small/115986.png",
    category: "Drinks",
    isAvailable: true,
    stock: 20,
    featured: false,
    displayOnGift: false,
    displayOnMenu: true
  },
  {
    name: "Blueberry Muffin",
    description: "Buttery vanilla cake with berries dusted with granulated sugar and topped with sweet crumb.",
    price: 330,
    image: "https://starbucksstatic.cognizantorderserv.com/Items/Small/100075.jpg",
    category: "Food",
    isAvailable: true,
    stock: 12,
    featured: false,
    displayOnGift: false,
    displayOnMenu: true
  },
  {
    name: "India Exclusive Gift Card",
    description: "Bring in the festive season and make each celebration memorable with our exclusive India design.",
    price: 99,
    image: "https://preprodtsbstorage.blob.core.windows.net/cms/uploads/TSB_GC_indiacard_1_1_28dafb2bb6.png",
    category: "Gifts",
    isAvailable: true,
    stock: 50,
    featured: true,
    displayOnGift: true,
    displayOnMenu: false
  },
  {
    name: "Starbucks Coffee Gift Card",
    description: "Starbucks is best when shared. Treat your pals to a good cup of coffee.",
    price: 88,
    image: "https://preprodtsbstorage.blob.core.windows.net/cms/uploads/71d3780c_be6e_46b1_ab01_8a2bce244a7f_1_1_2d1afadaa0.png",
    category: "Gifts",
    isAvailable: true,
    stock: 45,
    featured: false,
    displayOnGift: true,
    displayOnMenu: false
  },
  {
    name: "Keep Me Warm Gift Card",
    description: "Captivating, cosy, coffee. Gift your loved ones this Starbucks Gift Card.",
    price: 50,
    image: "https://preprodtsbstorage.blob.core.windows.net/cms/uploads/7c6f7c64_3f89_4ba2_9af8_45fc6d94ad35_1_1bdd3bf075.webp",
    category: "Gifts",
    isAvailable: true,
    stock: 30,
    featured: false,
    displayOnGift: true,
    displayOnMenu: false
  },
  {
    name: "Cold Coffee",
    description: "Refreshing cold coffee with rich flavor and smooth texture, perfect for hot days.",
    price: 278,
    image: "https://starbucksstatic.cognizantorderserv.com/Items/Small/100433.jpg",
    category: "Drinks",
    isAvailable: true,
    stock: 18,
    featured: false,
    displayOnGift: false,
    displayOnMenu: true
  },
  {
    name: "Chicken Sandwich",
    description: "Marinated tandoori chicken filling, sliced cheese, and whole grain bread.",
    price: 283,
    image: "https://starbucksstatic.cognizantorderserv.com/Items/Small/100100_1.png",
    category: "Food",
    isAvailable: true,
    stock: 10,
    featured: false,
    displayOnGift: false,
    displayOnMenu: true
  }
];

async function seedProducts() {
  try {
    // Connect to MongoDB
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');

    // Clear existing products
    await Product.deleteMany({});
    console.log('Cleared existing products');

    // Insert new products
    const insertedProducts = await Product.insertMany(sampleProducts);
    console.log(`Successfully inserted ${insertedProducts.length} products`);

    // Display inserted products
    console.log('\nInserted products:');
    insertedProducts.forEach(product => {
      console.log(`- ${product.name} (₹${product.price}) - Menu: ${product.displayOnMenu}, Gift: ${product.displayOnGift}`);
    });

    console.log('\nSeeding completed successfully!');
  } catch (error) {
    console.error('Error seeding products:', error);
  } finally {
    // Close connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  }
}

// Run the seeding function
seedProducts();
