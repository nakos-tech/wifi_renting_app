function validateReferralCode() {
  var referralCode = document.getElementById("referral_code").value;
  var validCodes = ["WIFI123", "FREE2024", "CONNECT50"]; // Example valid codes
  var messageElement = document.getElementById("referral_message");

  if (validCodes.includes(referralCode.trim().toUpperCase())) {
      messageElement.style.color = "green";
      messageElement.textContent = "✅ Code valid! You now have WiFi access.";
  } else {
      messageElement.style.color = "red";
      messageElement.textContent = "❌ Invalid code! Please try again.";
  }
}
