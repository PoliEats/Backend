import cookieParser from "cookie-parser";
import express from "express";
import { createServer } from "node:http";
import cors from "npm:cors";
import { Server } from "npm:socket.io";
import { MockDatabase } from "./database/MockDatabase.ts";
import { addMessage } from "./lc/model.ts";
import { ValidateJWT } from "./middlewares/ValidateJWT.ts";
import { AuthenticationService } from "./services/AuthenticationService.ts";

const app = express();

// Instantiate the services
const db = new MockDatabase();
const authenticationService = new AuthenticationService(db);
const JWTmiddleware = new ValidateJWT(authenticationService);

app.use(cookieParser());
app.use(express.json());

app.use(cors({
  origin: "*",
}));

export const wsServer = createServer(app);
export const io = new Server(wsServer, {
  cors: {
    origin: "*",
  },
});

app.get("/", (_req, res) => {
  res.send("Welcome to the Dinosaur API!");
});

app.post("/auth/register", async (req, res) => {
  const { name, email, document, password } = req.body;
  try {
    const userId = await authenticationService.registerUser(
      {
        id: 123,
        name,
        email,
        document,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      password,
    );

    const token = await authenticationService.createJWT(userId);

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
    });

    res.status(201).send();
  } catch (error: unknown) {
    if (!(error instanceof Error)) {
      throw error;
    }

    res.status(400).json({ error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const userId = await authenticationService.loginUser(email, password);
    if (!userId) {
      res.status(401).json({ error: "Invalid email or password" });
      return;
    }

    const token = await authenticationService.createJWT(userId.id);
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
    });

    res.status(200).send();
  } catch (error: unknown) {
    if (!(error instanceof Error)) {
      throw error;
    }

    res.status(401).json({ error: "Email ou senha inválidos." });
  }
});

app.get("/hidden", JWTmiddleware.validateToken, (_req, res) => {
  res.status(200).json({ message: "This is a hidden route" });
});

// Handle messages from chat
export const pendingConfirmation = new Map();

io.on("connection", (socket) => {
  socket.on("message", async (e) => {
    await addMessage(e).then((final) => {
      socket.emit("message", final);
    });
  });

  socket.on("order_confirmation", (e) => {
    const { orderId, type } = JSON.parse(e);
    if (pendingConfirmation.has(orderId)) {
      const { resolve } = pendingConfirmation.get(orderId);
      pendingConfirmation.delete(orderId);
      if (type === "confirm") {
        resolve(true);
      } else {
        resolve(false);
      }
    }
  });

  socket.emit(
    "message",
    JSON.stringify({
      type: "welcome",
      message:
        "Olá, tudo bem ?, bem vindo ao PoliEats! Sou um assistente virtual e estou aqui para te ajudar com o que você precisar. Você pode me perguntar sobre o cardápio, horários de funcionamento, fazer pedidos e consultar o status dos pedidos em andamento. Como posso te ajudar hoje? 🤗",
    }),
  );
});

wsServer.listen(8000);
console.log(`Server is running on http://localhost:8000`);
