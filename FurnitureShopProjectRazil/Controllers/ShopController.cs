using FurnitureShopProjectRazil.Data;
using FurnitureShopProjectRazil.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace FurnitureShopProjectRazil.Controllers
{
    public class ShopController : Controller
    {
        private readonly AppDbContext _context;

        public ShopController(AppDbContext context)
        {
            _context = context;
        }

        // GET: Shop
        public async Task<IActionResult> Index()
        {
            List<Products> products = await _context.Products.ToListAsync();
            return View(products);
        }

        // GET: Shop/Details/5 (Opsional, məhsul detal səhifəsi üçün)
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var product = await _context.Products.FirstOrDefaultAsync(m => m.Id == id);
            if (product == null)
            {
                return NotFound();
            }

            return View(product); // Ayrı bir Details.cshtml view-u lazımdır
        }
    }
}