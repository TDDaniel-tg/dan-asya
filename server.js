require("dotenv").config();
const express    = require("express");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const cors       = require("cors");
const path       = require("path");
const bodyParser = require("body-parser");

const app = express();

// Подключение к MongoDB
mongoose
  .connect(process.env.MONGO_URI)  // Удалены параметры useNewUrlParser и useUnifiedTopology
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

// Модель пользователя для обычных пользователей
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model("User", UserSchema);

// Главная страница (например, index.html)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Регистрация обычного пользователя (админ через регистрацию не создаётся)
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Проверка существования пользователя
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: "Имя пользователя или почта уже заняты" });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Создание и сохранение нового пользователя
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "Регистрация успешна" });
  } catch (error) {
    console.error("Ошибка регистрации:", error);
    res.status(500).json({ message: "Ошибка сервера", error });
  }
});

// Логин: если введены фиксированные админские данные из .env, выдаётся токен с ролью "admin",
// иначе происходит стандартная аутентификация обычного пользователя.
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    // Проверка на админские данные, заданные в .env
    if (
      usernameOrEmail === process.env.ADMIN_USERNAME &&
      password === process.env.ADMIN_PASSWORD
    ) {
      // Если данные совпадают – выдаём токен с ролью "admin"
      const token = jwt.sign({ id: "admin", role: "admin" }, process.env.JWT_SECRET, { expiresIn: "7d" });
      return res.json({ message: "Вход выполнен (админ)", token });
    }

    // Если введённые данные не соответствуют админским – ищем пользователя в базе
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
    });

    if (!user) {
      return res.status(400).json({ message: "Неверное имя пользователя или почта" });
    }

    // Проверка пароля для обычного пользователя
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Неверный пароль" });
    }

    // Выдача токена с ролью "user"
    const token = jwt.sign({ id: user._id, role: "user" }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Вход выполнен", token });
  } catch (error) {
    console.error("Ошибка входа:", error);
    res.status(500).json({ message: "Ошибка сервера", error });
  }
});

// Пример защищённого маршрута (при необходимости, можно добавить middleware проверки токена)
app.get("/api/protected", (req, res) => {
  res.json({ message: "Этот маршрут защищён" });
});

// Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
