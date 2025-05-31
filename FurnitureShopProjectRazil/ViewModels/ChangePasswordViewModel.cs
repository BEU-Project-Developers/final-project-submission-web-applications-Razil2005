using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class ChangePasswordViewModel
    {
        [Required(ErrorMessage = "Cari parol tələb olunur.")]
        [DataType(DataType.Password)]
        [Display(Name = "Cari Parolunuz")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Yeni parol tələb olunur.")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Yeni parol ən az 6 simvol olmalıdır.")]
        // Parolun mürəkkəbliyi üçün RegularExpression əlavə edə bilərsiniz
        [Display(Name = "Yeni Parolunuz")]
        public string NewPassword { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword), ErrorMessage = "Yeni parol və təkrar parol eyni deyil.")]
        [Display(Name = "Yeni Parolu Təsdiqləyin")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}