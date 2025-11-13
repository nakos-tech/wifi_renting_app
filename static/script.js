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

document.querySelectorAll('.buy-btn').forEach(btn => {
  btn.addEventListener('click', function(e) {
      e.preventDefault();
      const planName = this.closest('.package').querySelector('h3').textContent;
      const amount = this.closest('.package').querySelector('p').textContent;
      alert(`You selected ${planName} - ${amount}\nPrompting MPESA...`);
      // Here, send fetch() or redirect to /start_payment endpoint
  });
});
