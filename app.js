import express from "express";
import cors from "cors";
import signale from "signale";
import helmet from "helmet";
import http from "http";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());
app.use(cors({
    origin: [process.env.ALLOWED_DOMAIN]
}));

app.use(helmet());

/** @type {[{email: string, password: string}]} */
let users = [{ email: "julio.cruzazul@hotmail.com", password: bcrypt.hashSync("123", 12) }];

app.post('/register', async function (req, res) {
    try {
        const { email, password } = req.body;
        if (users.find((user) => user.email === email)) {
            return res.status(400).json({
                success: false,
                message: "el usuario ya existe"
            });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = { email, password: hashedPassword };
        users.push(newUser);
        signale.info(users);
        return res.status(200).json({
            success: true,
            user: newUser,
            message: "registro exitoso"
        });
    } catch (error) {
        signale.error(error);
        return res.status(500).json({
            success: false,
            message: error
        });
    }
});

app.post('/login', async function (req, res) {
    try {
        const { email, password } = req.body;
        const foundUser = users.find((user) => user.email === email);
        if (!foundUser) {
            return res.status(404).json({
                success: false,
                message: "no existe el usuario"
            });
        }
        const authorized = await bcrypt.compare(password, foundUser.password);
        if (!authorized) {
            return res.status(401).json({
                success: false,
                message: "contraseña incorrecta"
            });
        }
        const token = jwt.sign({ email: foundUser.email }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });
        return res.status(200).json({
            success: true,
            token,
            message: "login exitoso"
        });
    } catch (error) {
        signale.error(error);
        return res.status(500).json({
            success: false,
            message: error
        });
    }
});

app.get('/auth/token', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Se espera el token en el header Authorization: Bearer <token>
    if (!token) {
        return res.status(400).json({
            success: false,
            message: 'Token no proporcionado'
        });
    }

    try {
        // Verificar el token y extraer la información
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Verificar si el token tiene la propiedad email (o lo que sea necesario en tu payload)
        if (decoded.email) {
            return res.status(200).json({
                success: true,
                message: 'Token validado',
                email: decoded.email
            });
        } else {
            return res.status(401).json({
                success: false,
                message: 'Token inválido'
            });
        }
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Error al verificar el token'
        });
    }
});

app.delete('/delete', (req, res) => {
    let token = req.headers['authorization']?.split(' ')[1];
    token = jwt.decode(token, JWT_SECRET);
    signale.info("actualidad\n" + existe(token.email)); 
    const userToRemove = users.findIndex((foundUser) => foundUser.email === token.email);
    users.splice(userToRemove, 1);
    signale.info("actualidad\n" + existe(token.email));
    return res.status(200).json({
        success: true,
        message: "elemento borrado"
    });
});


app.put('/edit', (req, res) => {
    let token = req.headers['authorization']?.split(' ')[1];
    token = jwt.decode(token, JWT_SECRET); 
    const newEmail = req.body.email;
    signale.info("actualidad\n" + existe(token.email));
    users = users.map((user) =>
        user.email === token.email ? { ...user, email: newEmail } : user
    );
    signale.star("actualidad nueva\n" + existe(token.email));
    token.email = newEmail;
    token = jwt.sign(token, JWT_SECRET);
    return res.status(200).json({
        success: true,
        message: "usuario editado",
        email: newEmail,
        token
    });
});

app.get('/', (req, res) => {
    return res.status(200).json({
        users
    }); 
});

function existe(email) {
    return users.findIndex((user) => user.email === email) !== -1;
}

const server = http.createServer(app);

server.listen(9000, () => signale.success("api corriendo en http://localhost:9000"));