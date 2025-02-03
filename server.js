require("dotenv").config();
const express    = require("express");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const cors       = require("cors");
const path       = require("path");
const bodyParser = require("body-parser");
const multer     = require("multer");

const app = express();

// Подключение к MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB подключена"))
  .catch((err) => console.log("❌ Ошибка подключения к MongoDB:", err));

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// Раздача статических файлов (папки с публичными ресурсами)
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname, "css")));
app.use(express.static(path.join(__dirname, "js")));
app.use(express.static(path.join(__dirname, "photo")));
app.use(express.static(path.join(__dirname, "html")));

// Раздаем загруженные файлы из папки uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Настройка multer для загрузки файлов
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // файлы будут сохраняться в папке uploads
  },
  filename: function (req, file, cb) {
    // Формируем имя файла: fieldname-<timestamp>.<расширение>
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + Date.now() + ext);
  }
});
const upload = multer({ storage });

// Модель пользователя
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model("User", UserSchema);

// Модель товара
const ProductSchema = new mongoose.Schema({
  name:        { type: String, required: true },
  price:       { type: Number, required: true },
  description: { type: String, required: true },
  image:       { type: String, required: true } // путь к загруженному файлу
});
const Product = mongoose.model("Product", ProductSchema);

// Главная страница (например, index.html)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "html", "index.html"));
});

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: "Имя пользователя или почта уже заняты" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "Регистрация успешна" });
  } catch (error) {
    console.error("Ошибка регистрации:", error);
    res.status(500).json({ message: "Ошибка сервера", error });
  }
});

// Логин
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    // Проверка на админские данные из .env
    if (
      usernameOrEmail === process.env.ADMIN_USERNAME &&
      password === process.env.ADMIN_PASSWORD
    ) {
      const token = jwt.sign({ id: "admin", role: "admin" }, process.env.JWT_SECRET, { expiresIn: "7d" });
      return res.json({ message: "Вход выполнен (админ)", token });
    }

    // Поиск пользователя
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
    });
    if (!user) {
      return res.status(400).json({ message: "Неверное имя пользователя или почта" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Неверный пароль" });
    }
    const token = jwt.sign({ id: user._id, role: "user" }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Вход выполнен", token });
  } catch (error) {
    console.error("Ошибка входа:", error);
    res.status(500).json({ message: "Ошибка сервера", error });
  }
});

// Middleware для проверки токена
function authenticateToken(req, res, next) {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Токен не предоставлен" });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("Ошибка верификации токена:", err);
      return res.status(403).json({ message: "Неверный или истёкший токен" });
    }
    req.user = decoded;
    next();
  });
}

// Middleware для проверки роли admin с дополнительным логированием
function isAdmin(req, res, next) {
  console.log("Проверка роли пользователя. Декодированный токен:", req.user);
  if (req.user.role !== "admin") {
    console.error("Ошибка доступа: требуется роль admin, получено:", req.user.role);
    return res.status(403).json({ message: "Доступ запрещён. Требуется роль admin" });
  }
  next();
}

// Добавление товара (админ) с дополнительным логированием
app.post("/api/products", authenticateToken, isAdmin, upload.single("productImage"), async (req, res) => {
  try {
    console.log("Данные формы:", req.body);
    console.log("Файл:", req.file);

    const { productName, productPrice, productDescription } = req.body;
    if (!req.file) {
      console.error("Ошибка: файл изображения не передан");
      return res.status(400).json({ message: "Файл изображения не был загружен" });
    }
    if (!productName || !productPrice || !productDescription) {
      console.error("Ошибка: не все обязательные поля заполнены");
      return res.status(400).json({ message: "Все поля обязательны" });
    }
    const imagePath = `/uploads/${req.file.filename}`;
    const product = new Product({
      name: productName,
      price: Number(productPrice),
      description: productDescription,
      image: imagePath
    });
    await product.save();
    console.log("Товар успешно добавлен:", product);
    res.status(201).json({ message: "Товар успешно добавлен", product });
  } catch (error) {
    console.error("Ошибка добавления товара:", error);
    res.status(500).json({ message: "Ошибка при добавлении товара" });
  }
});

// Удаление товара (админ)
app.delete("/api/products/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const productId = req.params.id;
    const deletedProduct = await Product.findByIdAndDelete(productId);
    if (!deletedProduct) {
      return res.status(404).json({ message: "Товар не найден" });
    }
    console.log("Товар удалён:", deletedProduct);
    res.json({ message: "Товар удалён", product: deletedProduct });
  } catch (error) {
    console.error("Ошибка удаления товара:", error);
    res.status(500).json({ message: "Ошибка при удалении товара" });
  }
});

// Получение списка всех товаров
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find({});
    res.json(products);
  } catch (error) {
    console.error("Ошибка получения товаров:", error);
    res.status(500).json({ message: "Ошибка при получении товаров" });
  }
});

// Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
