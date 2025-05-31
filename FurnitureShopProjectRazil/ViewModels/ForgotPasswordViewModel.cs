using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required(ErrorMessage = "E-poçt ünvanı tələb olunur.")]
        [EmailAddress(ErrorMessage = "Düzgün e-poçt formatı daxil edin.")]
        [Display(Name = "Qeydiyyatdan keçdiyiniz e-poçt ünvanı")]
        [StringLength(100)]
        public string Email { get; set; } = string.Empty;
    }
}