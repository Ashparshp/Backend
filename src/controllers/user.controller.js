import { asyncHandler } from "../utils/asyncHandler.js";
import { APIError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) => {
  // Get user details from frontend
  const { fullname, username, email, password } = req.body;

  // Validate user details - not empty
  if (!fullname || !username || !email || !password) {
    throw new APIError(400, "Please fill in all fields");
  }

  // Check if user already exists: username, email
  const existingUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existingUser) {
    throw new APIError(409, "User already exists");
  }
  // Check for Images, Avatar
  const avatarLocalPath = req.files?.avatar[0]?.path;
  const coverImageLocalPath = req.files?.coverImage[0]?.path;

  if (!avatarLocalPath || !coverImageLocalPath) {
    throw new APIError(400, "Avatar and Cover Image are required");
  }
  // Upload images to cloudinary, Check avatar as well
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar || !coverImage) {
    throw new APIError(500, "Avatar and Cover Image upload failed");
  }
  // Create user object - create entry in database
  const user = await User.create({
    fullName,
    username: username.toLowerCase(),
    email,
    password,
    avatar: avatar.url,
    coverImage: coverImage.url,
  });

  // Remove password and refresh token from response
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  // Check for user creation
  if (!createdUser) {
    throw new APIError(500, "User registration failed");
  }
  // Send response back to frontend
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
});

export { registerUser };
