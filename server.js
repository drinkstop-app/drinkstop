require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const jwt = require('jsonwebtoken');
const SibApiV3Sdk = require('@getbrevo/brevo');

const app = express();

app.use(express.json());
app.use(cors());

// --- 1. POŁĄCZENIE Z BAZĄ DANYCH ---
const dbLink = process.env.MONGO_URI;

mongoose.connect(dbLink)
    .then(() => console.log('✅ Udało się! Połączono z bazą MongoDB Drink Stop.'))
    .catch((err) => console.error('❌ Błąd połączenia z bazą danych:', err));

// --- 2. SCHEMAT UŻYTKOWNIKA ---
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    age: Number,
    city: String,
    password: String,
    isVerified: { type: Boolean, default: false }, 
    verificationToken: String,
    resetPasswordToken: String,      // Token do resetu hasła
    resetPasswordExpires: Date       // Czas wygaśnięcia tokenu
});
const User = mongoose.model('User', userSchema);

// --- 3. KONFIGURACJA API BREVO ---
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = process.env.BREVO_API_KEY;
const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

// --- 4. REJESTRACJA ---
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, age, city, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Ten e-mail jest już zajęty!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const token = crypto.randomBytes(32).toString('hex'); 

        const newUser = new User({
            name, email, age, city, password: hashedPassword, verificationToken: token
        });

        await newUser.save();

        const verificationLink = `https://drinkstop-backend.onrender.com/api/verify/${token}`;
        
        // WYSYŁKA MAILA PRZEZ BREVO API
        await apiInstance.sendTransacEmail({
            sender: { email: process.env.EMAIL_FROM || "noreply@drinkstop.pl", name: "Drink Stop" },
            to: [{ email: email }],
            subject: 'Potwierdź swój adres e-mail w Drink Stop! 🍻',
            htmlContent: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <h2 style="color: #f5a623;">Witaj w Drink Stop, ${name}!</h2>
                    <p>Aby w pełni korzystać z aplikacji, aktywuj swoje konto:</p>
                    <a href="${verificationLink}" style="display: inline-block; padding: 12px 24px; background-color: #f5a623; color: #000; text-decoration: none; border-radius: 8px; font-weight: bold; margin-top: 20px;">Aktywuj konto 🍻</a>
                </div>
            `
        });

        res.status(201).json({ message: 'Konto utworzone! Sprawdź swoją skrzynkę e-mail, aby je aktywować.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Wystąpił błąd serwera' });
    }
});

// --- 5. AKTYWACJA KONTA ---
app.get('/api/verify/:token', async (req, res) => {
    try {
        const user = await User.findOne({ verificationToken: req.params.token });
        if (!user) return res.status(400).send('<h1 style="color:red; text-align:center; margin-top:50px;">Błąd! Nieprawidłowy lub wygasły link.</h1>');

        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();

        res.send(`
    <div style="font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #121212; color: white; height: 100vh; padding-top: 50px;">
        <h1 style="color: #90c83a;">Konto zostało aktywowane! ✅</h1>
        <p>Możesz teraz wrócić do aplikacji Drink Stop i się zalogować.</p>
        <a href="https://drinkstop-backend.onrender.com" style="color: #f5a623; font-weight: bold; text-decoration: none; font-size: 18px;">Wróć do aplikacji</a>
    </div>
`);
    } catch (error) {
        res.status(500).send('Wystąpił błąd podczas aktywacji.');
    }
});

// --- 6. LOGOWANIE ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Nie znaleziono konta z tym adresem e-mail.' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Konto nie jest aktywne! Kliknij w link wysłany na Twój e-mail.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Błędne hasło. Spróbuj ponownie.' });
        }

        const token = jwt.sign({ id: user._id }, 'nasz_tajny_klucz_123', { expiresIn: '7d' });

        res.json({
            message: 'Zalogowano pomyślnie!',
            token,
            user: { name: user.name, age: user.age, city: user.city }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera podczas logowania.' });
    }
});

// --- 7. ZAPOMNIANE HASŁO (WYSYŁKA MAILA) ---
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(400).json({ message: 'Nie znaleziono konta z tym adresem e-mail.' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 15 * 60 * 1000; // 15 minut
        await user.save();

        const resetLink = `https://drinkstop-backend.onrender.com/reset.html?token=${token}`;

        // WYSYŁKA MAILA PRZEZ BREVO API
        await apiInstance.sendTransacEmail({
            sender: { email: process.env.EMAIL_FROM || "noreply@drinkstop.pl", name: "Drink Stop" },
            to: [{ email: email }],
            subject: 'Resetowanie hasła w Drink Stop 🔑',
            htmlContent: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <h2 style="color: #f5a623;">Resetowanie hasła</h2>
                    <p>Otrzymaliśmy prośbę o zresetowanie hasła do Twojego konta. Kliknij w poniższy przycisk:</p>
                    <a href="${resetLink}" style="display: inline-block; padding: 12px 24px; background-color: #f5a623; color: #000; text-decoration: none; border-radius: 8px; font-weight: bold; margin-top: 20px;">Zresetuj hasło 🔑</a>
                    <p style="margin-top: 20px; font-size: 12px; color: #888;">Link jest ważny przez 15 minut.</p>
                </div>
            `
        });

        res.json({ message: 'Link do resetowania hasła został wysłany na Twój e-mail!' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 8. ZAPIS NOWEGO HASŁA ---
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Token jest nieprawidłowy lub wygasł.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.json({ message: 'Hasło zostało pomyślnie zmienione! Możesz się teraz zalogować.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 9. START SERWERA ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Serwer działa! Otwórz: http://localhost:${PORT}`);
});
