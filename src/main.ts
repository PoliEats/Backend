import cookieParser from "cookie-parser";
import express from "express";
import { createServer } from "node:http";
import cors from "npm:cors";
import { Server } from "npm:socket.io";
import { PostgresDatabase } from "./database/PostgresDatabase.ts";
import { OrderHandler } from "./handlers/OrderHandler.ts";
import { ProductHandler } from "./handlers/ProductHandler.ts";
import { addMessage } from "./lc/model.ts";
import { ValidateJWT } from "./middlewares/ValidateJWT.ts";
import { AuthenticationService } from "./services/AuthenticationService.ts";

// Importing the Socket interface from socket.io
declare module "npm:socket.io" {
  interface Socket {
    user?: {
      id: number;
      name: string;
    };
  }
}

const app = express();

// Instantiate the services
const db = new PostgresDatabase();
const authenticationService = new AuthenticationService(db);
const JWTmiddleware = new ValidateJWT(authenticationService);

// Instantiate the handlers
export const orderHandler = new OrderHandler(db);
export const productHandler = new ProductHandler(db);

app.use(cookieParser());
app.use(express.json());

app.use(cors({
  origin: [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173", // Add alternative localhost address
  ],
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "Origin",
    "X-Requested-With",
    "Accept",
  ],
  credentials: true,
  exposedHeaders: ["Authorization"], // Important for Clerk
}));

export const wsServer = createServer(app);
export const io = new Server(wsServer, {
  cors: {
    origin: [
      "http://localhost:5173",
      "http://localhost:3000",
      "http://127.0.0.1:5173", // Add alternative localhost address
    ],
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Origin",
      "X-Requested-With",
      "Accept",
    ],
    credentials: true,
    exposedHeaders: ["Authorization"], // Important for Clerk
  },
});

app.post("/auth/register", async (req, res) => {
  const { name, document, email, password, confirmPassword} = req.body;
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

    res.status(201).json({
      message: "Usuário cadastrado com sucesso",
      data: {
        id: userId,
        name,
        email,
        document,
      },
    });
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

// Order section
app.post("/order", JWTmiddleware.validateToken, async (req, res) => {
  const order = req.body;
  const userId = req.user!.id;

  const result = await orderHandler.createOrder(order, userId as number);

  res.status(result.status).json({
    message: result.message,
    data: result.data,
    error: result.error,
  });
});

app.get("/order/:id", JWTmiddleware.validateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user!.id;

  const result = await orderHandler.getOrderById(Number(id), userId as number);

  res.status(result.status).json({
    message: result.message,
    data: result.data,
    error: result.error,
  });
});

// TODO: Add JWT validation
app.get("/orders", async (_req, res) => {
  const result = await orderHandler.getOrders();

  res.status(result.status).json({
    message: result.message,
    data: result.data,
    error: result.error,
  });
});

app.delete("/order/:id", JWTmiddleware.validateToken, async (req, res) => {
  const { id } = req.params;

  const result = await orderHandler.deleteOrder(Number(id));

  res.status(result.status).json({
    message: result.message,
    data: result.data,
    error: result.error,
  });
});

// TODO: Add JWT validation
app.patch("/order/:id", async (req, res) => {
  const { id } = req.params;
  const { status, paymentMethod } = req.body;
  // const _userId = req.user!.id;

  const result = await orderHandler.updateOrderStatus(
    Number(id),
    status,
    paymentMethod ? paymentMethod : undefined,
  );

  res.status(result.status).json({
    message: result.message,
    data: result.data,
    error: result.error,
  });
});
// TODO: Add JWT validation
// Product section
app.post("/product", async (req, res) => {
  const product = req.body;

  const result = await productHandler.createProduct(product);

  res.status(result.status).json({
    message: result.message,
    data: result.data,
    error: result.error,
  });
});

app.get("/product/:id", JWTmiddleware.validateToken, async (req, res) => {
  const { id } = req.params;

  const result = await productHandler.getProductById(Number(id));
  res.status(result.status).json({
    message: result.message,
    data: result.data,
    error: result.error,
  });
});

// TODO: Add JWT validation
app.get("/products", async (_req, res) => {
  const result = await productHandler.getProducts();
  res.status(result.status).json({
    message: result.message,
    data: result.data,
    error: result.error,
  });
});

app.get("/hidden", JWTmiddleware.validateToken, (_req, res) => {
  res.status(200).json({ message: "This is a hidden route" });
});

// Handle messages from chat
export const pendingConfirmation = new Map();

export const userIds = new Map();

io.use((socket, next) => {
  // const token = socket.handshake.headers.cookie?.split("=")[1];
  // if (!token) {
  //   return next(new Error("Authentication error"));
  // }

  // await authenticationService.verifyJWT(token)
  //   .then((user) => {
  //     if (!user) {
  //       return next(new Error("Authentication error"));
  //     }
  //     //@ts-ignore just to avoid the error
  //     socket.user = user;
  //     next();
  //   })
  //   .catch(() => {
  //     return next(new Error("Authentication error"));
  //   });

  socket.user = {
    id: 2,
    name: "Lucas",
  };

  next();
});

io.on("connection", (socket) => {
  socket.on("message", async (e) => {
    await addMessage({ message: e, user: socket.user! }).then((final) => {
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
