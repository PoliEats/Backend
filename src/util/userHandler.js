require("dotenv").config();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

class UserHandler {
	#userSchema = new mongoose.Schema({
		username: { type: String, required: true },
		password: { type: String, required: true },
		salt: { type: String, required: true },
		role: { type: String, required: true },
		createdAt: { type: Date, default: Date.now },
	});

	#tokenSchema = new mongoose.Schema({
		token: { type: String, required: true },
		username: { type: String, required: true },
		createdAt: { type: Date, default: Date.now },
	});

	#databaseConnection;

	// Validates a JWT token
	validateJWT(token) {
		try {
			jwt.verify(token, process.env.SECRET_TOKEN);
		} catch (err) {
			throw err;
		}
	}

	// Creates a JWT token
	createJWT(username, role) {
		var token = jwt.sign(
			{ username: username, role: role },
			process.env.SECRET_TOKEN,
			{ expiresIn: "1d" }
		);
		return token;
	}

	// Hashes a password with a salt
	hashPassword(passwd, salt) {
		if (!salt) {
			var salt = crypto.randomBytes(32).toString("hex");
		}
		return [
			crypto.pbkdf2Sync(passwd, salt, 2000, 64, "sha512").toString("hex"),
			salt,
		];
	}

	// Validates a user exists
	async validateUser(user) {
		if (
			!(await this.#databaseConnection
				.model("User", this.#userSchema)
				.exists({ username: user.username }))
		) {
			throw new Error(`User not found with name ${user.username}`);
		}

		return true;
	}

	// Creates a user
	async createUser(user) {
		var [hashedPasswd, salt] = this.hashPassword(user.password);

		try {
			if (
				await this.#databaseConnection
				.model("User", this.#userSchema)
				.exists({ username: user.username })
			) {
				throw new Error(`User already exists with name ${user.username}`);
			}

			await this.#databaseConnection
				.model("User", this.#userSchema)
				.create({
					username: user.username,
					password: hashedPasswd,
					salt: salt,
					role: user.role ? user.role : "user",
				});

			return await this.#databaseConnection
				.model("User", this.#userSchema)
				.find();
		} catch (error) {
			throw error;
		}
	}

	// Retrieves a user by username
	async getUser(username) {
		try {
			return await this.#databaseConnection
				.model("User", this.#userSchema)
				.findOne({ username: username });
		} catch (err) {
			throw err;
		}
	}

	// Retrieves all users
	async getUsers() {
		return await this.#databaseConnection
			.model("User", this.#userSchema)
			.find();
	}

	// Deletes a user
	async deleteUser(user) {
		try {
			await this.validateUser(user);

			var selUser = await this.getUser(user.username);

			if (selUser.role === "admin") {
				throw new Error("Cannot delete admin user");
			}

			await this.#databaseConnection
				.model("User", this.#userSchema)
				.deleteOne({ username: user.username });
		} catch (err) {
			throw err;
		}
	}

	// Creates a recovery token
	async createRecoveryToken(user) {
		try {
			await this.validateUser(user);

			var token = crypto.randomBytes(16).toString("hex");

			await this.#databaseConnection
				.model("Token", this.#tokenSchema)
				.create({ token: token, username: user.username });

			return token;
		} catch (err) {
			throw err;
		}
	}

	// Deletes a recovery token
	async deleteToken(token) {
		try {
			await this.#databaseConnection
				.model("Token", this.#tokenSchema)
				.deleteOne({ token: token });
		} catch (err) {
			throw err;
		}
	}

	// Attempts to validate a recovery token
	async validateToken(token) {
		try {
			var selToken = await this.#databaseConnection
				.model("Token", this.#tokenSchema)
				.findOne({ token: token });
			await this.deleteToken(token);
			return selToken;
		} catch (err) {
			throw err;
		}
	}

	// Attempts to authenticate a user
	async authenticateUser(user) {
		try {
			await this.validateUser(user);

			const selUser = await this.getUser(user.username);
			const hashedPasswd = this.hashPassword(user.password, selUser.salt);

			if (hashedPasswd[0] === selUser.password) {
				return this.createJWT(user.username, user.role);
			} else {
				throw new Error("Invalid password");
			}
		} catch (err) {
			throw err;
		}
	}

	// Changes the user password
	async changePassword(newPassword, token) {
		var [hashedPasswd, salt] = this.hashPassword(newPassword);
		try {
			var token = await this.validateToken(token);
			var user = await this.getUser(token.username);

			await this.#databaseConnection
				.model("User", this.#userSchema)
				.updateOne(
					{ username: user.username },
					{ password: hashedPasswd, salt: salt }
				);
		} catch (err) {
			throw err;
		}
	}
	// Constructs the UserHandler object with database connection
	constructor(conn) {
		this.#databaseConnection = conn;
	}
}

module.exports = UserHandler;
