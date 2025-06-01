using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FurnitureShopProjectRazil.Models
{
  
    public class Contact
    {
        [Key] 
        public int Id { get; set; }

        [Required(ErrorMessage = "Ünvan sahəsi boş buraxıla bilməz.")]
        [StringLength(250, ErrorMessage = "Ünvan maksimum 250 simvol olmalıdır.")]
        [Display(Name = "Şirkət Ünvanı")]
        public string Address { get; set; }

        [Required(ErrorMessage = "E-poçt ünvanı boş buraxıla bilməz.")]
        [EmailAddress(ErrorMessage = "Düzgün e-poçt formatı daxil edin.")]
        [StringLength(100, ErrorMessage = "E-poçt maksimum 100 simvol olmalıdır.")]
        [Display(Name = "Əlaqə E-poçtu")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Telefon nömrəsi boş buraxıla bilməz.")]
        [Phone(ErrorMessage = "Düzgün telefon nömrəsi formatı daxil edin.")]
        [StringLength(30, ErrorMessage = "Telefon nömrəsi maksimum 30 simvol olmalıdır.")]
        [Display(Name = "Əlaqə Nömrəsi")]
        
        public string Phone { get; set; }
    }
}