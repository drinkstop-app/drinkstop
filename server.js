require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const jwt = require('jsonwebtoken');

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
    resetPasswordToken: String,        
    resetPasswordExpires: Date,
    status: { type: String, default: 'free' },
    interests: { type: String, default: '' },
    desc: { type: String, default: '' },
    photo: { type: String, default: '' },
    marketingConsent: { type: Boolean, default: false },
    deletionRequested: { type: Boolean, default: false },
    deletionDate: { type: Date, default: null },
    eventCredits: { type: Number, default: 0 } // Pula pakietów B2B dla eventów
});
const User = mongoose.model('User', userSchema);

// --- SCHEMAT WYJŚCIA (PINEZKI) Z AUTOMATYCZNYM WYGASZANIAM PO 3 GODZINACH ---
const outingSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    name: String,
    city: String,
    location: String,
    plans: String,
    desc: String,
    coordinates: [Number], // [longitude, latitude]
    createdAt: { 
        type: Date, 
        default: Date.now, 
        expires: 10800 // Automatyczne usunięcie z bazy po 3 godzinach (10800 sekund)
    } 
});
const Outing = mongoose.model('Outing', outingSchema);

// --- FUNKCJA POMOCNICZA DO WYSYŁKI MAILI PRZEZ API BREVO ---
async function sendBrevoEmail(toEmail, subject, htmlContent) {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
            'accept': 'application/json',
            'api-key': process.env.BREVO_API_KEY,
            'content-type': 'application/json'
        },
        body: JSON.stringify({
            sender: { email: process.env.EMAIL_FROM || "noreply@drinkstop.pl", name: "Drink Stop" },
            to: [{ email: toEmail }],
            subject: subject,
            htmlContent: htmlContent
        })
    });

    if (!response.ok) {
        const errData = await response.json();
        throw new Error(JSON.stringify(errData));
    }
    return await response.json();
}

// --- 4. REJESTRACJA ---
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, age, city, password, photo, marketingConsent } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Ten e-mail jest już zajęty!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const token = crypto.randomBytes(32).toString('hex'); 

        const newUser = new User({
            name, 
            email, 
            age, 
            city, 
            password: hashedPassword, 
            verificationToken: token, 
            photo: photo || '',
            marketingConsent: marketingConsent || false
        });

        await newUser.save();

        const protocol = req.protocol;
        const host = req.get('host');
        const verificationLink = `${protocol}://${host}/api/verify/${token}`;
        
        await sendBrevoEmail(
            email,
            'Potwierdź swój adres e-mail w Drink Stop! 🍻',
            `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
                    <h2 style="color: #f5a623; margin-bottom: 10px;">Witaj w Drink Stop, ${name}!</h2>
                    <p style="color: #333; font-size: 15px;">Aby w pełni korzystać z aplikacji, aktywuj swoje konto:</p>
                    
                    <a href="${verificationLink}" style="display: inline-block; padding: 12px 24px; background-color: #f5a623; color: #000; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0;">Aktywuj konto 🍻</a>
                    
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0 20px 0;">
                    
                    <p style="color: #888; font-size: 12px; line-height: 1.5; margin: 0;">
                        Wiadomość została wygenerowana automatycznie, prosimy na nią nie odpowiadać.<br>
                        Jeśli to nie Ty zakładałeś konto w aplikacji Drink Stop, po prostu zignoruj tę wiadomość.
                    </p>
                </div>
            `
        );

        res.status(201).json({ message: 'Konto utworzone! Sprawdź swoją skrzynkę e-mail, aby je aktywować.' });

    } catch (error) {
        console.error('Błąd wysyłki e-maila:', error);
        res.status(500).json({ message: 'Wystąpił błąd serwera podczas wysyłania e-maila' });
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
                <p>Możesz teraz bezpiecznie zamknąć tę kartę i zalogować się w aplikacji.</p>
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

        if (user.deletionRequested) {
            user.deletionRequested = false;
            user.deletionDate = null;
            await user.save();

            await sendBrevoEmail(
                email,
                'Super, że wracasz! Konto zostało uratowane 🍻',
                `
                    <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
                        <h2 style="color: #90c83a; margin-bottom: 10px;">Cieszymy się, że z nami zostajesz!</h2>
                        <p style="color: #333; font-size: 15px;">Zauważyliśmy, że zalogowałeś się ponownie do aplikacji <b>Drink Stop</b>.</p>
                        <p style="color: #555; font-size: 14px;">Procedura usuwania Twojego konta została <b>automatycznie anulowana</b>. Wszystkie Twoje dane i pinezki są w pełni bezpieczne.</p>
                        <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0 20px 0;">
                        <p style="color: #888; font-size: 12px; line-height: 1.5; margin: 0;">
                            Pozdrawiamy,<br>Zespół Drink Stop 🍻
                        </p>
                    </div>
                `
            );
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
            user: { 
                name: user.name, 
                age: user.age, 
                city: user.city,
                status: user.status,
                interests: user.interests,
                desc: user.desc,
                photo: user.photo,
                eventCredits: user.eventCredits || 0
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera podczas logowania.' });
    }
});

// --- 7. ZAPOMNIANE HASŁO ---
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(400).json({ message: 'Nie znaleziono konta z tym adresem e-mail.' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 15 * 60 * 1000; 
        await user.save();

        const protocol = req.protocol;
        const host = req.get('host');
        const resetLink = `${protocol}://${host}/reset.html?token=${token}`;

        await sendBrevoEmail(
            email,
            'Resetowanie hasła w Drink Stop 🔑',
            `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <h2 style="color: #f5a623;">Resetowanie hasła</h2>
                    <p>Otrzymaliśmy prośbę o zresetowanie hasła do Twojego konta. Kliknij w poniższy przycisk:</p>
                    <a href="${resetLink}" style="display: inline-block; padding: 12px 24px; background-color: #f5a623; color: #000; text-decoration: none; border-radius: 8px; font-weight: bold; margin-top: 20px;">Zresetuj hasło 🔑</a>
                    <p style="margin-top: 20px; font-size: 12px; color: #888;">Link jest ważny przez 15 minut.</p>
                </div>
            `
        );

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

// --- 9. AKTUALIZACJA PROFILU ---
app.post('/api/update-profile', async (req, res) => {
    try {
        const { email, name, age, city, interests, desc, photo } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }

        if (name) user.name = name;
        if (age) user.age = age;
        if (city) user.city = city;
        if (interests !== undefined) user.interests = interests;
        if (desc !== undefined) user.desc = desc;
        if (photo !== undefined) user.photo = photo;

        await user.save();

        res.json({ 
            message: 'Profil zaktualizowany pomyślnie!',
            user: {
                name: user.name,
                age: user.age,
                city: user.city,
                status: user.status,
                interests: user.interests,
                desc: user.desc,
                photo: user.photo,
                eventCredits: user.eventCredits || 0
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera podczas aktualizacji profilu.' });
    }
});

// --- 10. AKTYWACJA PREMIUM ---
app.post('/api/activate-premium', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }

        user.status = 'premium';
        await user.save();

        res.json({ message: 'Konto zostało pomyślnie zaktualizowane do wersji Premium! 👑', status: 'premium' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd podczas aktywacji pakietu.' });
    }
});

// --- 10.1 TESTOWY ENDPOINT PŁATNOŚCI (SIMULATOR) ---
app.post('/api/test-payment', async (req, res) => {
    try {
        const { email, type, plan } = req.body; 
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }

        if (type === 'premium') {
            user.status = 'premium';
            await user.save();
            return res.json({ message: 'Płatność testowa zakończona sukcesem! Konto Premium aktywowane.', status: 'premium' });
        } 
        
        if (type === 'b2b') {
            const addedCredits = plan === '1' ? 1 : plan === '5' ? 5 : plan === '10' ? 10 : 0;
            user.eventCredits = (user.eventCredits || 0) + addedCredits;
            await user.save();
            return res.json({ message: `Płatność testowa zakończona sukcesem! Dodano ${addedCredits} oznaczeń eventowych.`, eventCredits: user.eventCredits });
        }

        res.status(400).json({ message: 'Nieznany typ płatności.' });
    } catch (error) {
        console.error('Błąd testowej płatności:', error);
        res.status(500).json({ message: 'Błąd serwera podczas przetwarzania płatności.' });
    }
});

// --- 11. ENDPOINTY DLA PINEZEK (WYJŚĆ) ---

app.get('/api/outings', async (req, res) => {
    try {
        const outings = await Outing.find({});
        res.json(outings);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania wyjść.' });
    }
});

app.post('/api/outings', async (req, res) => {
    try {
        const { userEmail, name, city, location, plans, desc, coordinates } = req.body;
        const newOuting = new Outing({
            userEmail, name, city, location, plans, desc, coordinates
        });

        await newOuting.save();
        res.status(201).json({ message: 'Wyjście opublikowane pomyślnie!', outing: newOuting });
    } catch (error) {
        res.status(500).json({ message: 'Błąd podczas publikowania wyjścia.' });
    }
});

app.delete('/api/outings/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { email } = req.body;

        const outing = await Outing.findById(id);
        if (!outing) {
            return res.status(404).json({ message: 'Nie znaleziono takiego wyjścia.' });
        }

        if (outing.userEmail !== email) {
            return res.status(403).json({ message: 'Nie masz uprawnień do usunięcia tej pinezki!' });
        }

        await Outing.findByIdAndDelete(id);
        res.json({ message: 'Pinezka została usunięta.' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera podczas usuwania.' });
    }
});

// --- SCHEMAT PROŚB I WIADOMOŚCI ---
const messageSchema = new mongoose.Schema({
    senderEmail: String,
    senderName: String,
    receiverEmail: String,
    receiverName: String, 
    message: String,
    type: { type: String, default: 'chat' }, 
    status: { type: String, default: 'pending' }, 
    deliveryStatus: { type: String, default: 'sent' }, // 'sent' (1 szary), 'delivered' (2 szare), 'read' (2 niebieskie)
    createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// --- WYSŁANIE PROŚBY / WIADOMOŚCI ---
app.post('/api/messages', async (req, res) => {
    try {
        const { senderEmail, senderName, receiverEmail, receiverName, message, type } = req.body;
        const newMessage = new Message({ 
            senderEmail, 
            senderName, 
            receiverEmail, 
            receiverName, 
            message, 
            type, 
            deliveryStatus: 'sent' 
        });
        await newMessage.save();
        res.status(201).json({ message: 'Wiadomość wysłana pomyślnie!', data: newMessage });
    } catch (error) {
        res.status(500).json({ message: 'Błąd podczas wysyłania wiadomości.' });
    }
});

// --- OZNACZENIE JAKO DOSTARCZONE ---
app.post('/api/messages/delivered', async (req, res) => {
    try {
        const { myEmail } = req.body;
        await Message.updateMany(
            { receiverEmail: myEmail, deliveryStatus: 'sent' },
            { $set: { deliveryStatus: 'delivered' } }
        );
        res.json({ message: 'Wiadomości oznaczone jako dostarczone.' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd.' });
    }
});

// --- OZNACZENIE JAKO ODCZYTANE ---
app.post('/api/messages/read', async (req, res) => {
    try {
        const { myEmail, partnerEmail } = req.body;
        await Message.updateMany(
            { senderEmail: partnerEmail, receiverEmail: myEmail, deliveryStatus: { $ne: 'read' } },
            { $set: { deliveryStatus: 'read' } }
        );
        res.json({ message: 'Wiadomości oznaczone jako przeczytane.' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd.' });
    }
});

// --- POBIERANIE WIADOMOŚCI/PROŚB DANEGO UŻYTKOWNIKA ---
app.get('/api/messages/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const messages = await Message.find({ 
            $or: [{ receiverEmail: email }, { senderEmail: email }] 
        }).sort({ createdAt: 1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania wiadomości.' });
    }
});

// --- AKCEPTACJA PROŚBY ---
app.patch('/api/messages/accept/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updatedMessage = await Message.findByIdAndUpdate(
            id, 
            { status: 'accepted' }, 
            { new: true }
        );
        if (!updatedMessage) {
            return res.status(404).json({ message: 'Nie znaleziono prośby.' });
        }
        res.json({ message: 'Prośba została zaakceptowana!', data: updatedMessage });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera podczas akceptacji prośby.' });
    }
});

// --- POBIERANIE PROFILU UŻYTKOWNIKA PO E-MAILU ---
app.get('/api/user/:email', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.params.email });
        if (!user) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }
        res.json({
            name: user.name,
            age: user.age,
            city: user.city,
            interests: user.interests,
            desc: user.desc,
            photo: user.photo,
            joined: '26 sierpnia 2026',
            eventCredits: user.eventCredits || 0
        });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 13. ŻĄDANIE USUNIĘCIA KONTA ---
app.post('/api/request-deletion', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }

        user.deletionRequested = true;
        user.deletionDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        await user.save();

        await sendBrevoEmail(
            email,
            'Szkoda, że odchodzisz z Drink Stop 😢',
            `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
                    <h2 style="color: #ff4757; margin-bottom: 10px;">Z przykrością przyjęliśmy Twoją prośbę</h2>
                    <p style="color: #333; font-size: 15px;">Otrzymaliśmy zgłoszenie usunięcia Twojego konta w aplikacji <b>Drink Stop</b>.</p>
                    <p style="color: #555; font-size: 14px;">Twoje konto zostanie całkowicie usunięte za <b>30 dni</b>. Jeśli zmienisz zdanie, wystarczy, że po prostu zalogujesz się ponownie przed upływem tego terminu, a proces usuwania zostanie automatycznie anulowany.</p>
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0 20px 0;">
                    <p style="color: #888; font-size: 12px; line-height: 1.5; margin: 0;">
                        Pozdrawiamy,<br>Zespół Drink Stop 🍻
                    </p>
                </div>
            `
        );

        res.json({ message: 'Zlecono usunięcie konta i wysłano e-mail.' });
    } catch (error) {
        console.error('Błąd usuwania konta:', error);
        res.status(500).json({ message: 'Błąd serwera podczas żądania usunięcia konta.' });
    }
});

// --- 12. START SERWERA ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Serwer działa! Otwórz: http://localhost:${PORT}`);
});
