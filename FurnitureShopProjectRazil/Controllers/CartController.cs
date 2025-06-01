using FurnitureShopProjectRazil.Data;
using FurnitureShopProjectRazil.Models;
using FurnitureShopProjectRazil.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging; // Logger üçün əlavə etdim
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace FurnitureShopProjectRazil.Controllers
{
    [Authorize]
    public class CartController : Controller
    {
        private readonly AppDbContext _context;
        private readonly ILogger<CartController> _logger; // Logger

        public CartController(AppDbContext context, ILogger<CartController> logger) // Logger DI
        {
            _context = context;
            _logger = logger;
        }

        // Köməkçi metod: Cari istifadəçinin ID-sini alır
        private bool TryGetUserId(out int userId)
        {
            userId = 0;
            var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdStr) || !int.TryParse(userIdStr, out userId))
            {
                _logger.LogWarning("GetCurrentUserCartAsync: User ID not found in claims or is not a valid integer. User authenticated: {IsAuthenticated}", User.Identity.IsAuthenticated);
                return false;
            }
            return true;
        }

        private async Task<Cart?> GetCurrentUserCartAsync(bool createIfNotExists = false)
        {
            if (!TryGetUserId(out int userId))
            {
                return null; // İstifadəçi ID-si tapılmadı və ya düzgün deyil
            }

            var cart = await _context.Carts
                                     .Include(c => c.Items)
                                        .ThenInclude(i => i.Product) // Product məlumatlarını da yükləyək
                                     .FirstOrDefaultAsync(c => c.UserId == userId);

            if (cart == null && createIfNotExists)
            {
                _logger.LogInformation("No cart found for user {UserId}. Creating a new cart.", userId);
                cart = new Cart { UserId = userId, CreatedDate = DateTime.UtcNow };
                _context.Carts.Add(cart);
                try
                {
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("New cart created with ID {CartId} for user {UserId}.", cart.Id, userId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error creating a new cart for user {UserId}.", userId);
                    return null; // Səbət yaradılarkən xəta baş verərsə
                }
            }
            else if (cart != null)
            {
                _logger.LogDebug("Cart found with ID {CartId} for user {UserId} with {ItemCount} items.", cart.Id, userId, cart.Items.Count);
            }
            else
            {
                _logger.LogDebug("No cart found for user {UserId} and createIfNotExists is false.", userId);
            }

            return cart;
        }

        // GET: Cart
        public async Task<IActionResult> Index()
        {
            var dbCart = await GetCurrentUserCartAsync();
            var cartViewModel = new CartViewModel();

            if (dbCart != null && dbCart.Items.Any())
            {
                foreach (var dbItem in dbCart.Items)
                {
                    if (dbItem.Product == null) // Əgər Product yüklənməyibsə (ThenInclude ilə yüklənməlidir)
                    {
                        _logger.LogWarning("CartItem {CartItemId} for cart {CartId} has a null Product. ProductId: {ProductId}", dbItem.Id, dbCart.Id, dbItem.ProductId);
                        // Bu məhsulu ötürə və ya xəta verə bilərsiniz
                        continue;
                    }
                    cartViewModel.Items.Add(new CartItemViewModel
                    {
                        ProductId = dbItem.ProductId,
                        ProductName = dbItem.Product.Title,
                        ProductImagePath = dbItem.Product.ImagePath,
                        Price = dbItem.UnitPrice,
                        Quantity = dbItem.Quantity
                    });
                }
            }
            else if (dbCart == null && User.Identity.IsAuthenticated) // İstifadəçi daxil olub amma səbəti null gəlibsə
            {
                _logger.LogWarning("User {UserId} is authenticated but GetCurrentUserCartAsync returned null.", User.FindFirstValue(ClaimTypes.NameIdentifier));
                // İstəsəniz burada TempData ilə bir xəta mesajı göstərə bilərsiniz
                // TempData["ErrorMessage"] = "Səbətinizə daxil olmaq mümkün olmadı.";
            }
            // else if (dbCart != null && !dbCart.Items.Any()) { // Səbət var amma boşdur, bu normaldır }

            return View(cartViewModel);
        }

        // POST: Cart/AddToCart
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddToCart(int productId, int quantity = 1)
        {
            // İstifadəçi autentifikasiyasını yoxlamaq üçün TryGetUserId-dən istifadə etməyə ehtiyac yoxdur,
            // çünki [Authorize] atributu bunu təmin edir. Amma GetCurrentUserCartAsync onsuz da bunu edir.

            if (quantity <= 0) quantity = 1;

            var product = await _context.Products.FindAsync(productId);
            if (product == null)
            {
                TempData["ErrorMessage"] = "Məhsul tapılmadı.";
                _logger.LogWarning("AddToCart: Product with ID {ProductId} not found.", productId);
                return RedirectToAction("Index", "Shop");
            }

            var cart = await GetCurrentUserCartAsync(createIfNotExists: true);
            if (cart == null)
            {
                TempData["ErrorMessage"] = "Səbətinizə daxil olmaq mümkün olmadı və ya yeni səbət yaradıla bilmədi.";
                _logger.LogError("AddToCart: Failed to get or create cart for user {UserId} for product {ProductId}.", User.FindFirstValue(ClaimTypes.NameIdentifier), productId);
                return RedirectToAction("Index", "Shop"); // Və ya Login səhifəsinə yönləndir
            }

            var cartItem = await _context.CartItems
                                         .FirstOrDefaultAsync(ci => ci.CartId == cart.Id && ci.ProductId == productId);

            if (cartItem == null)
            {
                cartItem = new CartItem
                {
                    CartId = cart.Id,
                    ProductId = productId,
                    Quantity = quantity,
                    UnitPrice = product.Price
                };
                _context.CartItems.Add(cartItem);
                _logger.LogInformation("New item ProductId:{ProductId} added to CartId:{CartId} for UserId:{UserId}.", productId, cart.Id, cart.UserId);
            }
            else
            {
                cartItem.Quantity += quantity;
                _logger.LogInformation("Quantity of item ProductId:{ProductId} in CartId:{CartId} for UserId:{UserId} updated to {NewQuantity}.", productId, cart.Id, cart.UserId, cartItem.Quantity);
            }
            cart.LastModifiedDate = DateTime.UtcNow;

            try
            {
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = $"'{product.Title}' səbətə uğurla əlavə edildi!";
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "DbUpdateException in AddToCart for ProductId:{ProductId}, CartId:{CartId}, UserId:{UserId}", productId, cart.Id, cart.UserId);
                TempData["ErrorMessage"] = "Məhsul səbətə əlavə edilərkən verilənlər bazası xətası baş verdi.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "General exception in AddToCart for ProductId:{ProductId}, CartId:{CartId}, UserId:{UserId}", productId, cart.Id, cart.UserId);
                TempData["ErrorMessage"] = "Məhsul səbətə əlavə edilərkən naməlum xəta baş verdi.";
            }

            // Əgər AJAX istifadə etsəydik, JSON cavabı qaytarardıq.
            // Hazırda səhifə yenilənməsi ilə işləyirik.
            return RedirectToAction("Index", "Shop");
        }

        // UpdateQuantity və RemoveFromCart metodları da GetCurrentUserCartAsync-ı istifadə edəcək
        // və oxşar null yoxlamalarına malik olmalıdır.

        // POST: Cart/UpdateQuantity
      
      
        // POST: Cart/RemoveFromCart
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveFromCart(int productId)
        {
            var cart = await GetCurrentUserCartAsync();
            if (cart == null)
            {
                TempData["ErrorMessage"] = "Səbətiniz tapılmadı.";
                return RedirectToAction("Index"); // Və ya başqa bir səhifə
            }

            var cartItem = await _context.CartItems
                                   .FirstOrDefaultAsync(ci => ci.CartId == cart.Id && ci.ProductId == productId);

            if (cartItem != null)
            {
                _context.CartItems.Remove(cartItem);
                cart.LastModifiedDate = DateTime.UtcNow;
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Məhsul səbətdən silindi.";
                _logger.LogInformation("Item ProductId:{ProductId} removed from CartId:{CartId}.", productId, cart.Id);
            }
            else
            {
                _logger.LogWarning("RemoveFromCart: CartItem with ProductId {ProductId} not found in CartId {CartId}.", productId, cart.Id);
                TempData["ErrorMessage"] = "Silmək istədiyiniz məhsul səbətinizdə tapılmadı.";
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateQuantity(int productId, int quantity)
        {
            var cart = await GetCurrentUserCartAsync();
            if (cart == null)
            {
                return Json(new { success = false, message = "Səbətiniz tapılmadı və ya daxil olmamısınız." });
            }

            var cartItemEntity = await _context.CartItems
                                         .Include(ci => ci.Product) // Product məlumatını da yükləyək
                                         .FirstOrDefaultAsync(ci => ci.CartId == cart.Id && ci.ProductId == productId);

            bool itemRemoved = false;
            if (cartItemEntity != null)
            {
                if (quantity <= 0)
                {
                    _context.CartItems.Remove(cartItemEntity);
                    itemRemoved = true;
                    _logger.LogInformation("Item ProductId:{ProductId} removed from CartId:{CartId} due to quantity <= 0.", productId, cart.Id);
                }
                else
                {
                    cartItemEntity.Quantity = quantity;
                    _logger.LogInformation("Quantity of item ProductId:{ProductId} in CartId:{CartId} updated to {NewQuantity}.", productId, cart.Id, quantity);
                }
                cart.LastModifiedDate = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                // Yenilənmiş səbət məlumatlarını ViewModel-ə çevirib qaytaraq
                var updatedDbCart = await _context.Carts
                                                  .Include(c => c.Items)
                                                  .ThenInclude(i => i.Product)
                                                  .AsNoTracking() // Yalnız oxumaq üçün
                                                  .FirstOrDefaultAsync(c => c.Id == cart.Id);

                var cartViewModel = new CartViewModel();
                if (updatedDbCart != null && updatedDbCart.Items.Any())
                {
                    cartViewModel.Items = updatedDbCart.Items.Select(dbItem => new CartItemViewModel
                    {
                        ProductId = dbItem.ProductId,
                        ProductName = dbItem.Product.Title,
                        ProductImagePath = dbItem.Product.ImagePath,
                        Price = dbItem.UnitPrice,
                        Quantity = dbItem.Quantity
                        // TotalPrice ViewModel-də hesablanır
                    }).ToList();
                }

                return Json(new
                {
                    success = true,
                    message = itemRemoved ? "Məhsul səbətdən silindi." : "Səbət yeniləndi.",
                    productId = productId,
                    newQuantity = itemRemoved ? 0 : cartItemEntity?.Quantity ?? 0, // Əgər silinibsə 0, yoxsa yeni say
                    newTotalPriceForItem = itemRemoved ? 0 : (cartItemEntity?.UnitPrice ?? 0) * (cartItemEntity?.Quantity ?? 0),
                    newGrandTotal = cartViewModel.GrandTotal, // ViewModel-dən hesablanmış ümumi məbləğ
                    itemRemoved = itemRemoved,
                    cartItemCount = cartViewModel.Items.Sum(i => i.Quantity) // Ümumi məhsul sayı (navbar üçün)
                });
            }
            else
            {
                _logger.LogWarning("UpdateQuantity: CartItem with ProductId {ProductId} not found in CartId {CartId}.", productId, cart.Id);
                return Json(new { success = false, message = "Yeniləmək istədiyiniz məhsul səbətinizdə tapılmadı." });
            }
        }
    }
}