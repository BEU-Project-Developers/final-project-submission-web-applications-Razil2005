using FurnitureShopProjectRazil.Models; // Products modeli üçün

namespace FurnitureShopProjectRazil.ViewModels
{
    public class CartItemViewModel
    {
        public int ProductId { get; set; }
        public string ProductName { get; set; }
        public string? ProductImagePath { get; set; } // Nullable ola bilər
        public decimal Price { get; set; } // Səbətə əlavə edilərkənki qiymət (CartItem.UnitPrice-dən gələcək)
        public int Quantity { get; set; }
        public decimal TotalPrice => Price * Quantity;

        public CartItemViewModel() { }

       
        public CartItemViewModel(Products product, int quantity = 1)
        {
            ProductId = product.Id;
            ProductName = product.Title;
            ProductImagePath = product.ImagePath;
            Price = product.Price;
            Quantity = quantity;
        }

       
    }
}